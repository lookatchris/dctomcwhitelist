import discord
from discord import app_commands
import os
import re
import logging
import asyncio
import httpx
import struct
from dotenv import load_dotenv
from mcrcon import MCRcon
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Validate required environment variables
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
if not DISCORD_TOKEN:
    raise ValueError("DISCORD_TOKEN environment variable is required")

RCON_HOST = os.getenv('RCON_HOST')
if not RCON_HOST:
    raise ValueError("RCON_HOST environment variable is required")

try:
    RCON_PORT = int(os.getenv('RCON_PORT', 25575))
except (TypeError, ValueError):
    raise ValueError("RCON_PORT must be a valid integer")

RCON_PASSWORD = os.getenv('RCON_PASSWORD')
if not RCON_PASSWORD:
    raise ValueError("RCON_PASSWORD environment variable is required")

REQUEST_CHANNEL_ID_STR = os.getenv('REQUEST_CHANNEL_ID')
if not REQUEST_CHANNEL_ID_STR:
    raise ValueError("REQUEST_CHANNEL_ID environment variable is required")
try:
    REQUEST_CHANNEL_ID = int(REQUEST_CHANNEL_ID_STR)
except ValueError:
    raise ValueError("REQUEST_CHANNEL_ID must be a valid integer")

ADMIN_CHANNEL_ID_STR = os.getenv('ADMIN_CHANNEL_ID')
if not ADMIN_CHANNEL_ID_STR:
    raise ValueError("ADMIN_CHANNEL_ID environment variable is required")
try:
    ADMIN_CHANNEL_ID = int(ADMIN_CHANNEL_ID_STR)
except ValueError:
    raise ValueError("ADMIN_CHANNEL_ID must be a valid integer")

ADMIN_ROLE_ID_STR = os.getenv('ADMIN_ROLE_ID')
if not ADMIN_ROLE_ID_STR:
    raise ValueError("ADMIN_ROLE_ID environment variable is required")
try:
    ADMIN_ROLE_ID = int(ADMIN_ROLE_ID_STR)
except ValueError:
    raise ValueError("ADMIN_ROLE_ID must be a valid integer")

# Optional health check interval (seconds)
try:
    HEALTH_CHECK_INTERVAL = int(os.getenv('HEALTH_CHECK_INTERVAL', 3600))
except (TypeError, ValueError):
    HEALTH_CHECK_INTERVAL = 3600

# Optional health check enable/disable
ENABLE_HEALTH_CHECKS = os.getenv('ENABLE_HEALTH_CHECKS', 'true').lower() in ('true', '1', 'yes', 'on')

# Optional appeal category ID
APPEAL_CATEGORY_ID_STR = os.getenv('APPEAL_CATEGORY_ID')
APPEAL_CATEGORY_ID = None
if APPEAL_CATEGORY_ID_STR:
    try:
        APPEAL_CATEGORY_ID = int(APPEAL_CATEGORY_ID_STR)
    except ValueError:
        logger.warning("APPEAL_CATEGORY_ID must be a valid integer, ignoring")

# Setup Discord intents
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

class MyClient(discord.Client):
    def __init__(self, *, intents: discord.Intents):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self.executor = ThreadPoolExecutor(max_workers=2)

    async def setup_hook(self):
        await self.tree.sync()
        logger.info("Command tree synced")
        # Register persistent views so buttons continue working after restarts
        try:
            self.add_view(InvalidUsernameView())
            self.add_view(NonAppealableView())
            self.add_view(AppealableView())
            self.add_view(ClearConfirmView())
            logger.info("Persistent views registered")
        except Exception as e:
            logger.error(f"Failed to register persistent views: {e}")

client = MyClient(intents=intents)

# Track invalid request messages and bot error replies for cleanup
# Key: (channel_id, author_id) -> { 'user_msg': Message, 'error_msg': Message, 'task': asyncio.Task }
cleanup_map = {}

async def _delete_message_safe(msg):
    try:
        await msg.delete()
    except Exception as e:
        logger.warning(f"Failed to delete message {getattr(msg, 'id', None)}: {e}")

async def _cleanup_entry_now(key):
    entry = cleanup_map.get(key)
    if not entry:
        return
    task = entry.get('task')
    if task and not task.done():
        try:
            task.cancel()
        except Exception:
            pass
    # delete messages
    for m in [entry.get('user_msg'), entry.get('error_msg')]:
        if m:
            await _delete_message_safe(m)
    cleanup_map.pop(key, None)

async def _schedule_cleanup(key, user_msg, error_msg, delay_seconds=300):
    # cancel prior
    await _cleanup_entry_now(key)
    async def _runner():
        try:
            await asyncio.sleep(delay_seconds)
            # delete if still present
            await _delete_message_safe(user_msg)
            await _delete_message_safe(error_msg)
        finally:
            cleanup_map.pop(key, None)
    task = asyncio.create_task(_runner())
    cleanup_map[key] = {'user_msg': user_msg, 'error_msg': error_msg, 'task': task}


async def _delete_channel_after(channel: discord.TextChannel, delay_seconds: int):
    try:
        await asyncio.sleep(delay_seconds)
        await channel.delete(reason=f"Auto-cleanup after {delay_seconds} seconds")
    except Exception as e:
        logger.warning(f"Auto-delete appeal channel failed: {e}")


def is_valid_minecraft_username(username):
    """
    Validates a Minecraft username format.
    Minecraft usernames must be 3-16 characters, containing only letters, numbers, and underscores.
    """
    return bool(re.match(r'^[a-zA-Z0-9_]{3,16}$', username))


# Temporary channel helpers
def is_temporary_channel(channel: discord.abc.GuildChannel) -> bool:
    topic = getattr(channel, 'topic', '') or ''
    # Treat any channel in the configured appeal category as temporary
    try:
        category_id = getattr(channel, 'category_id', None)
        if category_id is None:
            cat = getattr(channel, 'category', None)
            category_id = getattr(cat, 'id', None) if cat else None
        if APPEAL_CATEGORY_ID and category_id == APPEAL_CATEGORY_ID:
            return True
    except Exception:
        pass
    return (
        'Appeal channel for whitelist denial' in topic or
        'Invalid username notification' in topic
    )


def can_user_close_channel(user: discord.Member, channel: discord.abc.GuildChannel) -> bool:
    """Admins can always close. For appeal channels, the denier can also close."""
    guild = user.guild
    if not guild:
        return False
    admin_role = guild.get_role(ADMIN_ROLE_ID)
    if admin_role and admin_role in getattr(user, 'roles', []):
        return True
    # Check denier for appeal channels
    topic = getattr(channel, 'topic', '') or ''
    if 'Appeal channel for whitelist denial' in topic:
        denier_id = AppealViewHelpers._parse_id(topic, 'denier')
        if denier_id and user.id == denier_id:
            return True
    return False


async def check_mojang_username(username):
    """
    Check if a Minecraft username exists via Mojang API.
    Returns (exists: bool, uuid: str or None, error: str or None)
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"https://api.mojang.com/users/profiles/minecraft/{username}")
            if response.status_code == 200:
                data = response.json()
                return (True, data.get('id'), None)
            elif response.status_code == 404:
                return (False, None, "Username does not exist")
            else:
                return (False, None, f"API returned status {response.status_code}")
    except httpx.TimeoutException:
        return (False, None, "Mojang API timeout")
    except Exception as e:
        return (False, None, f"API error: {str(e)}")


async def check_if_whitelisted(username):
    """Async wrapper to check if player is whitelisted."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(client.executor, _check_whitelist_sync, username)


class WhitelistRequestView(discord.ui.View):
    def __init__(self, username, request_message=None, request_user=None):
        super().__init__(timeout=None)
        self.username = username
        self.request_message = request_message
        self.request_user = request_user

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.green)
    async def approve_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Show modal for approval reason
        modal = ApprovalReasonModal(self.username, self.request_message, self.request_user)
        await interaction.response.send_modal(modal)

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.red)
    async def deny_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Show modal for denial reason
        modal = DenialReasonModal(self.username, self.request_message, self.request_user, interaction.user)
        await interaction.response.send_modal(modal)


# Base helper methods for appeal views
class AppealViewHelpers:
    @staticmethod
    def _parse_id(topic: str | None, key: str) -> int | None:
        if not topic:
            return None
        import re
        m = re.search(rf"{key}\s*:\s*(\d+)", topic)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                return None
        return None
    
    @staticmethod
    def _parse_bool(topic: str | None, key: str) -> bool:
        if not topic:
            return False
        import re
        m = re.search(rf"{key}\s*:\s*(True|False)", topic, re.IGNORECASE)
        if m:
            return m.group(1).lower() == 'true'
        return False

    @staticmethod
    def _is_admin_or_denier(interaction: discord.Interaction) -> bool:
        user = interaction.user
        guild = interaction.guild
        if not guild:
            return False
        denier_id = AppealViewHelpers._parse_id(getattr(interaction.channel, 'topic', None), 'denier')
        if denier_id and user.id == denier_id:
            return True
        admin_role = guild.get_role(ADMIN_ROLE_ID)
        if admin_role and admin_role in getattr(user, 'roles', []):
            return True
        return False

    @staticmethod
    def _is_request_user(interaction: discord.Interaction) -> bool:
        uid = AppealViewHelpers._parse_id(getattr(interaction.channel, 'topic', None), 'user')
        return uid is not None and interaction.user.id == uid


# View for invalid username notifications - only Acknowledge button
class InvalidUsernameView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Acknowledge", style=discord.ButtonStyle.primary, custom_id="invalid_username_ack_button")
    async def ack_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Allow anyone to acknowledge invalid username notifications
        # Show confirmation with buttons
        try:
            await interaction.response.send_message(
                "⚠️ Acknowledging will close this channel. Please confirm.",
                ephemeral=True,
                view=ConfirmAcknowledgeView(appealable=False)
            )
        except Exception as e:
            logger.error(f"Failed to show acknowledge confirmation: {e}")


# View for non-appealable denials - only Acknowledge button
class NonAppealableView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Acknowledge", style=discord.ButtonStyle.primary, custom_id="non_appeal_ack_button")
    async def ack_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        # if not AppealViewHelpers._is_request_user(interaction):
        #     await interaction.response.send_message("Only the requester can acknowledge this.", ephemeral=True)
        #     return
        # # Show confirmation with buttons
        try:
            await interaction.response.send_message(
                "⚠️ Acknowledging will close this channel. Please confirm.",
                ephemeral=True,
                view=ConfirmAcknowledgeView(appealable=False)
            )
        except Exception as e:
            logger.error(f"Failed to show acknowledge confirmation: {e}")


# View for appealable denials - Acknowledge + Close Appeal buttons
class AppealableView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Acknowledge", style=discord.ButtonStyle.primary, custom_id="appealable_ack_button")
    async def ack_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not AppealViewHelpers._is_request_user(interaction):
            await interaction.response.send_message("Only the requester can acknowledge this.", ephemeral=True)
            return
        # For appealable: hide channel from user and notify admins
        try:
            await interaction.response.send_message(
                "⚠️ Acknowledging will hide this channel from you and notify admins. The admins will then close or delete it. Are you sure?",
                ephemeral=True,
                view=ConfirmAcknowledgeView(appealable=True)
            )
        except Exception as e:
            logger.error(f"Failed to show acknowledge confirmation: {e}")

    @discord.ui.button(label="Close Appeal", style=discord.ButtonStyle.danger, custom_id="appealable_close_button")
    async def close_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not AppealViewHelpers._is_admin_or_denier(interaction):
            await interaction.response.send_message("You do not have permission to close this appeal.", ephemeral=True)
            return
        try:
            await interaction.response.send_message("Closing appeal and deleting channel...", ephemeral=True)
            await interaction.channel.delete(reason=f"Appeal closed by {interaction.user}")
        except Exception as e:
            logger.error(f"Failed to delete appeal channel: {e}")
            try:
                await interaction.followup.send(f"Failed to delete channel: {e}", ephemeral=True)
            except Exception:
                pass


class ConfirmAcknowledgeView(discord.ui.View):
    def __init__(self, appealable: bool = False):
        super().__init__(timeout=60)
        self.appealable = appealable

    @discord.ui.button(label="Yes, confirm!", style=discord.ButtonStyle.danger, custom_id="appeal_ack_confirm")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Only request user can confirm
        def _is_request_user(inter: discord.Interaction) -> bool:
            uid = AppealViewHelpers._parse_id(getattr(inter.channel, 'topic', None), 'user')
            return uid is not None and inter.user.id == uid
        if not _is_request_user(interaction):
            await interaction.response.send_message("Only the requester can close this appeal.", ephemeral=True)
            return
        
        if self.appealable:
            # Hide channel from user, notify admins
            try:
                channel = interaction.channel
                user = interaction.user
                
                # Remove read permissions for the user
                await channel.set_permissions(user, read_messages=False, reason="User acknowledged appeal")
                
                # Notify admins
                admin_role = interaction.guild.get_role(ADMIN_ROLE_ID)
                if admin_role:
                    await channel.send(f"{admin_role.mention} The user has acknowledged and can no longer see this channel. You may close it when ready.")
                
                await interaction.response.send_message("You have acknowledged this appeal. You can no longer see this channel.", ephemeral=True)
            except Exception as e:
                logger.error(f"Failed to hide channel from user: {e}")
                try:
                    await interaction.response.send_message(f"Failed to update channel: {e}", ephemeral=True)
                except Exception:
                    pass
        else:
            # Non-appealable: delete channel
            try:
                await interaction.response.send_message("Closing this channel...", ephemeral=True)
                await interaction.channel.delete(reason=f"Appeal acknowledged by requester {interaction.user}")
            except Exception as e:
                logger.error(f"Failed to delete appeal channel on confirm: {e}")
                try:
                    await interaction.followup.send(f"Failed to delete channel: {e}", ephemeral=True)
                except Exception:
                    pass

    @discord.ui.button(label="No, keep open", style=discord.ButtonStyle.secondary, custom_id="appeal_ack_cancel")
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message("Okay, keeping the appeal channel open.", ephemeral=True)


# Confirmation view for !clear command
class ClearConfirmView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=60)

    def _authorized(self, interaction: discord.Interaction) -> bool:
        # Same authorization as !close
        user = interaction.user if isinstance(interaction.user, discord.Member) else interaction.guild.get_member(interaction.user.id)
        return bool(user and can_user_close_channel(user, interaction.channel))

    @discord.ui.button(label="Yes, clear messages", style=discord.ButtonStyle.danger, custom_id="confirm_clear_yes")
    async def yes(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._authorized(interaction):
            await interaction.response.send_message("You do not have permission to clear this channel.", ephemeral=True)
            return
        try:
            await interaction.response.send_message("Clearing messages...", ephemeral=True)
            # Prefer purging non-pinned messages
            deleted = 0
            channel = interaction.channel
            try:
                def not_pinned(m: discord.Message) -> bool:
                    return not m.pinned
                deleted_messages = await channel.purge(limit=None, check=not_pinned, bulk=True)
                deleted = len(deleted_messages)
            except Exception as purge_err:
                logger.warning(f"Bulk purge failed, falling back to manual delete: {purge_err}")
                async for msg in channel.history(limit=None, oldest_first=True):
                    if not msg.pinned:
                        try:
                            await msg.delete()
                            deleted += 1
                        except Exception:
                            pass
            try:
                await interaction.followup.send(f"Cleared {deleted} messages (pinned kept).", ephemeral=True)
            except Exception:
                pass
        except Exception as e:
            logger.error(f"Failed to clear channel: {e}")
            try:
                await interaction.followup.send(f"Failed to clear: {e}", ephemeral=True)
            except Exception:
                pass

    @discord.ui.button(label="No, cancel", style=discord.ButtonStyle.secondary, custom_id="confirm_clear_no")
    async def no(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message("Clear cancelled.", ephemeral=True)


class ApprovalReasonModal(discord.ui.Modal, title="Approve Whitelist Request"):
    reason = discord.ui.TextInput(
        label="Approval Reason (optional)",
        placeholder="Provide a reason for approval",
        required=False,
        max_length=200
    )

    def __init__(self, username, request_message=None, request_user=None):
        super().__init__()
        self.username = username
        self.request_message = request_message
        self.request_user = request_user

    async def on_submit(self, interaction: discord.Interaction):
        try:
            # Validate username
            if not is_valid_minecraft_username(self.username):
                await interaction.response.send_message(
                    f"Invalid username format: {self.username}", 
                    ephemeral=True
                )
                return
            
            # Connect to RCON and whitelist the user
            with MCRcon(RCON_HOST, RCON_PASSWORD, RCON_PORT) as mcr:
                response = mcr.command(f"whitelist add {self.username}")
                logger.info(f"RCON Response: {response}")
            
            reason_text = str(self.reason) if self.reason else "No reason provided"
            
            # Update the admin message to show approval
            embed = interaction.message.embeds[0]
            embed.color = discord.Color.green()
            embed.title = "Whitelist Request - Approved"
            embed.add_field(name="Status", value="✅ Approved", inline=False)
            embed.add_field(name="Approved by", value=interaction.user.mention, inline=False)
            embed.add_field(name="Reason", value=reason_text, inline=False)
            
            await interaction.response.edit_message(embed=embed, view=None)
            
            # Add checkmark to original request message if available
            if self.request_message:
                try:
                    await self.request_message.add_reaction("✅")
                    # Remove pending hourglass if present
                    try:
                        await self.request_message.remove_reaction("⏳", interaction.client.user)
                    except Exception:
                        pass
                except Exception as e:
                    logger.error(f"Failed to add checkmark to request message: {e}")
            
        except Exception as e:
            await interaction.response.send_message(
                f"Error connecting to RCON or executing command: {str(e)}", 
                ephemeral=True
            )
            logger.error(f"RCON Error: {e}")


class DenialReasonModal(discord.ui.Modal, title="Deny Whitelist Request"):
    reason = discord.ui.TextInput(
        label="Denial Reason (optional)",
        placeholder="Provide a reason for denial",
        required=False,
        max_length=200
    )
    appeal_allowed = discord.ui.TextInput(
        label="Appeal allowed? (yes/no)",
        placeholder="yes",
        required=True,
        max_length=10
    )

    def __init__(self, username, request_message=None, request_user=None, admin=None):
        super().__init__()
        self.username = username
        self.request_message = request_message
        self.request_user = request_user
        self.admin = admin

    async def on_submit(self, interaction: discord.Interaction):
        try:
            reason_text = str(self.reason) if self.reason else "No reason provided"
            appeal_raw = (str(self.appeal_allowed) or "yes").strip().lower()
            appeal_possible = appeal_raw in ("yes", "y", "true", "1", "✅", "allowed", "ok")
            
            # Update the admin message to show denial
            embed = interaction.message.embeds[0]
            embed.color = discord.Color.red()
            embed.title = "Whitelist Request - Denied"
            embed.add_field(name="Status", value="❌ Denied", inline=False)
            embed.add_field(name="Denied by", value=interaction.user.mention, inline=False)
            embed.add_field(name="Reason", value=reason_text, inline=False)
            embed.add_field(name="Appeal", value=("✅ Possible" if appeal_possible else "❌ Not possible"), inline=False)
            
            await interaction.response.edit_message(embed=embed, view=None)
            
            # Delete original request message
            if self.request_message:
                try:
                    await self.request_message.delete()
                    logger.info(f"Deleted request message for {self.username}")
                except Exception as e:
                    logger.error(f"Failed to delete request message: {e}")
            
            # Create private channel to notify user
            if self.request_user:
                try:
                    guild = interaction.guild
                    if guild:
                        # Get category if configured
                        category = None
                        if APPEAL_CATEGORY_ID:
                            category = guild.get_channel(APPEAL_CATEGORY_ID)
                            if category and not isinstance(category, discord.CategoryChannel):
                                logger.warning(f"APPEAL_CATEGORY_ID {APPEAL_CATEGORY_ID} is not a category channel")
                                category = None
                        
                        # Create private channel with user and bot
                        private_channel = await guild.create_text_channel(
                            name=f"appeal-{self.request_user.name}",
                            topic=f"Appeal channel for whitelist denial of {self.username} | denier: {interaction.user.id} | user: {self.request_user.id} | appeal: {appeal_possible}",
                            category=category
                        )
                        
                        # Set permissions: only bot, user, denier, and admin role can see
                        # If appeal is possible, user can send messages; otherwise read-only
                        await private_channel.set_permissions(guild.default_role, view_channel=False)
                        await private_channel.set_permissions(self.request_user, view_channel=True, send_messages=appeal_possible)
                        await private_channel.set_permissions(interaction.client.user, view_channel=True, send_messages=True)
                        await private_channel.set_permissions(interaction.user, view_channel=True, send_messages=True)  # Add denier
                        
                        # Add admin role permissions
                        admin_role = guild.get_role(ADMIN_ROLE_ID)
                        if admin_role:
                            await private_channel.set_permissions(admin_role, view_channel=True, send_messages=True)
                        
                        # Send denial notification in the channel
                        deny_embed = discord.Embed(
                            title="Whitelist Request - Denied",
                            description=f"Your whitelist request for `{self.username}` has been **denied**.",
                            color=discord.Color.red()
                        )
                        deny_embed.add_field(name="Reason", value=reason_text, inline=False)
                        #deny_embed.add_field(name="Denied by", value=interaction.user.mention, inline=False)
                        if appeal_possible:
                            deny_embed.add_field(name="Next Steps", value=f"Appeal is possible. Use Acknowledge to close this appeal.", inline=False)
                            view = AppealableView()
                            admin_status = "✅ Appeal channel created"
                        else:
                            deny_embed.add_field(name="Next Steps", value=f"Appeal is not possible. Please acknowledge to close this message.", inline=False)
                            view = NonAppealableView()
                            admin_status = "❌ Appeal not possible (read-only channel)"

                        await private_channel.send(f"{self.request_user.mention}", embed=deny_embed, view=view)
                        # Reflect channel creation and appeal policy in the admin embed
                        try:
                            embed.add_field(name="Appeal Channel", value=admin_status, inline=False)
                            await interaction.message.edit(embed=embed)
                        except Exception as e:
                            logger.warning(f"Failed to update admin message with appeal info: {e}")
                        logger.info(f"Created private appeal channel {private_channel.name} for {self.request_user}")
                except Exception as e:
                    logger.error(f"Failed to create private appeal channel: {e}")
            
        except Exception as e:
            await interaction.response.send_message(
                f"Error processing denial: {str(e)}", 
                ephemeral=True
            )
            logger.error(f"Denial Error: {e}")


def _check_rcon_sync():
    """Synchronous RCON check to run in thread executor."""
    import socket
    try:
        # Directly use socket to avoid MCRcon's signal usage
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((RCON_HOST, RCON_PORT))
        sock.close()
        return (True, "Connection successful (basic check)")
    except socket.timeout:
        return (False, "Connection timeout")
    except socket.error as e:
        return (False, f"Socket error: {e}")
    except Exception as e:
        return (False, str(e))


def _rcon_exec_sync(command: str, timeout: float = 5.0):
    """Minimal RCON exec without signals; returns payload string or raises."""
    import socket
    def send_packet(sock, req_id, req_type, payload_str):
        payload = payload_str.encode('utf-8')
        length = 4 + 4 + len(payload) + 2  # id + type + payload + 2 null bytes
        packet = struct.pack('<iii', length, req_id, req_type) + payload + b'\x00\x00'
        sock.sendall(packet)
    def recv_packet(sock):
        # read length
        header = sock.recv(4)
        if not header or len(header) < 4:
            raise RuntimeError('RCON: incomplete header')
        (length,) = struct.unpack('<i', header)
        body = b''
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                break
            body += chunk
        if len(body) < 8:
            raise RuntimeError('RCON: incomplete body')
        req_id, req_type = struct.unpack('<ii', body[:8])
        payload = body[8:]
        # strip trailing two nulls if present
        if payload.endswith(b'\x00\x00'):
            payload = payload[:-2]
        return req_id, req_type, payload.decode('utf-8', errors='replace')

    sock = socket.create_connection((RCON_HOST, RCON_PORT), timeout=timeout)
    sock.settimeout(timeout)
    try:
        # authenticate
        send_packet(sock, 0x1234, 3, RCON_PASSWORD)
        rid, rtype, payload = recv_packet(sock)
        if rid == -1:
            raise RuntimeError('RCON auth failed')
        # exec command
        send_packet(sock, 0x1235, 2, command)
        rid, rtype, payload = recv_packet(sock)
        return payload
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _check_whitelist_sync(username):
    """Check if a player is whitelisted. Returns (is_whitelisted: bool, error: str or None)"""
    try:
        response = _rcon_exec_sync('whitelist list')
        if not response:
            return (False, None)
        # parse names after colon
        names_part = ''
        if ':' in response:
            names_part = response.split(':', 1)[1]
        names = [n.strip().lower() for n in names_part.split(',') if n.strip()]
        is_white = username.lower() in names
        logger.info(f"Whitelist check for {username}: {'YES' if is_white else 'NO'}")
        return (is_white, None)
    except Exception as e:
        logger.error(f"Error checking whitelist for {username}: {e}")
        return (False, str(e))


async def perform_health_check():
    """Run checks: guild presence, channel access, and RCON connectivity. Return a discord.Embed."""
    logger.info("Performing health check")
    embed = discord.Embed(title="Bot Health Check", color=discord.Color.blue())

    # Guild presence
    guild_count = len(client.guilds)
    embed.add_field(name="Guilds connected", value=str(guild_count), inline=False)

    # Channel access checks
    req_channel = client.get_channel(REQUEST_CHANNEL_ID)
    admin_channel = client.get_channel(ADMIN_CHANNEL_ID)

    def check_channel(channel):
        if not channel:
            return (False, "Not found")
        guild = getattr(channel, 'guild', None)
        member = None
        if guild:
            member = guild.get_member(client.user.id)
        if not member:
            return (False, "Bot not a member of channel's guild")
        perms = channel.permissions_for(member)
        ok = perms.view_channel and perms.send_messages
        details = []
        if not perms.view_channel:
            details.append("Cannot view")
        if not perms.send_messages:
            details.append("Cannot send")
        if ok:
            return (True, "OK")
        return (False, ", ".join(details) if details else "Insufficient permissions")

    req_ok, req_msg = check_channel(req_channel)
    admin_ok, admin_msg = check_channel(admin_channel)

    embed.add_field(name="Request channel access", value=("✅ OK" if req_ok else f"❌ {req_msg}"), inline=False)
    embed.add_field(name="Admin channel access", value=("✅ OK" if admin_ok else f"❌ {admin_msg}"), inline=False)

    # RCON connectivity check (non-blocking)
    try:
        loop = asyncio.get_event_loop()
        rcon_ok, rcon_msg = await loop.run_in_executor(client.executor, _check_rcon_sync)
        if rcon_ok:
            embed.add_field(name="RCON", value=f"✅ Connected — response: {rcon_msg}", inline=False)
        else:
            logger.error(f"RCON health check failed: {rcon_msg}")
            embed.add_field(name="RCON", value=f"❌ Error: {rcon_msg}", inline=False)
    except Exception as e:
        logger.error(f"RCON health check failed: {e}")
        embed.add_field(name="RCON", value=f"❌ Error: {e}", inline=False)

    return embed


async def send_health_report(target_channel=None):
    embed = await perform_health_check()
    channel = target_channel or client.get_channel(ADMIN_CHANNEL_ID)
    if channel:
        try:
            await channel.send(embed=embed)
        except discord.Forbidden:
            logger.error(f"Missing permissions to send to channel {channel.id}. Bot needs 'Send Messages' and 'View Channel' permissions.")
        except discord.HTTPException as e:
            logger.error(f"Failed to send health report (HTTP {e.status}): {e.text}")
        except Exception as e:
            logger.error(f"Failed to send health report: {e}")
    else:
        logger.error(f"Admin channel ({ADMIN_CHANNEL_ID}) not found; cannot send health report")


async def periodic_health_checks_loop():
    while True:
        try:
            await send_health_report()
        except Exception as e:
            logger.error(f"Periodic health check error: {e}")
        await asyncio.sleep(HEALTH_CHECK_INTERVAL)


async def scan_unhandled_requests():
    """Scan request channel for unhandled messages on startup."""
    logger.info("Scanning request channel for unhandled messages...")
    try:
        req_channel = client.get_channel(REQUEST_CHANNEL_ID)
        if not req_channel:
            logger.error(f"Cannot scan: request channel {REQUEST_CHANNEL_ID} not found")
            return
        
        # Fetch recent messages (limit to last 100)
        async for message in req_channel.history(limit=100):
            # Skip bot's own messages
            if message.author == client.user:
                continue
            
            # Check if message already has checkmark reaction
            has_checkmark = any(str(reaction.emoji) == "✅" for reaction in message.reactions)
            if has_checkmark:
                continue
            
            username = message.content.strip()
            
            # Validate format
            if not is_valid_minecraft_username(username):
                continue
            
            # Check if already whitelisted
            is_whitelisted, error = await check_if_whitelisted(username)
            if error:
                logger.warning(f"Could not check whitelist status for {username}: {error}")
                continue
            
            if is_whitelisted:
                # Already whitelisted, add checkmark
                await message.add_reaction("✅")
                logger.info(f"Found already whitelisted player: {username}")
                continue
            
            # Not whitelisted and no checkmark - process it
            logger.info(f"Processing unhandled request: {username}")
            
            # Check Mojang API
            exists, uuid, api_error = await check_mojang_username(username)
            if not exists:
                await message.add_reaction("❌")
                logger.info(f"Username {username} does not exist on Mojang")
                
                # Create notification channel for invalid username
                try:
                    guild = message.guild
                    if guild:
                        # Get category if configured
                        category = None
                        if APPEAL_CATEGORY_ID:
                            category = guild.get_channel(APPEAL_CATEGORY_ID)
                            if category and not isinstance(category, discord.CategoryChannel):
                                category = None
                        
                        # Create notification channel
                        notif_channel = await guild.create_text_channel(
                            name=f"invalid-{message.author.name}",
                            topic=f"Invalid username notification for {username} | user: {message.author.id}",
                            category=category
                        )
                        
                        # Set permissions: user read-only, admins can write
                        await notif_channel.set_permissions(guild.default_role, view_channel=False)
                        await notif_channel.set_permissions(message.author, view_channel=True, send_messages=False)
                        await notif_channel.set_permissions(client.user, view_channel=True, send_messages=True)
                        
                        admin_role = guild.get_role(ADMIN_ROLE_ID)
                        if admin_role:
                            await notif_channel.set_permissions(admin_role, view_channel=True, send_messages=True)
                        
                        # Send notification
                        notif_embed = discord.Embed(
                            title="Invalid Username",
                            description=f"The username `{username}` does not exist on Mojang's servers.",
                            color=discord.Color.red()
                        )
                        notif_embed.add_field(name="Requested by", value=message.author.mention, inline=False)
                        notif_embed.add_field(name="Original message", value=message.jump_url, inline=False)
                        if api_error:
                            notif_embed.add_field(name="Error", value=api_error, inline=False)
                        notif_embed.add_field(name="Action", value="Please verify the username spelling and re-request the whitelist in the request channel. This channel will be deleted after you acknowledge.", inline=False)
                        
                        await notif_channel.send(f"{message.author.mention}", embed=notif_embed, view=InvalidUsernameView())
                        
                        # Delete original message
                        try:
                            await message.delete()
                            logger.info(f"Deleted invalid request message from {message.author}")
                        except Exception as del_e:
                            logger.warning(f"Could not delete invalid message: {del_e}")
                        
                        logger.info(f"Created notification channel {notif_channel.name} for invalid username")
                except Exception as notif_e:
                    logger.error(f"Failed to create notification channel for invalid username: {notif_e}")
                
                continue
            
            # Mark as pending review and forward to admin (no checkmark until approved)
            try:
                await message.add_reaction("⏳")
            except Exception:
                pass
            
            view = WhitelistRequestView(username, request_message=message, request_user=message.author)
            embed = discord.Embed(
                title="Whitelist Request (Recovered)",
                description=f"Request found during startup scan",
                color=discord.Color.orange()
            )
            embed.add_field(name="Username", value=username, inline=False)
            if uuid:
                embed.add_field(name="UUID", value=uuid, inline=False)
            embed.add_field(name="Requested by", value=message.author.mention, inline=False)
            embed.add_field(name="Original message", value=message.jump_url, inline=False)
            
            admin_channel = client.get_channel(ADMIN_CHANNEL_ID)
            if admin_channel:
                await admin_channel.send(embed=embed, view=view)
        
        logger.info("Request channel scan complete")
    except Exception as e:
        logger.error(f"Error scanning request channel: {e}", exc_info=True)


@client.tree.command(name="health", description="Run bot health checks")
@app_commands.checks.has_role(ADMIN_ROLE_ID)
async def health_command(interaction: discord.Interaction):
    """Slash command to run health checks."""
    await interaction.response.defer(ephemeral=False)
    try:
        embed = await perform_health_check()
        await interaction.followup.send(embed=embed)
    except Exception as e:
        logger.error(f"Health command error: {e}")
        await interaction.followup.send(f"Error running health check: {e}", ephemeral=True)


@client.event
async def on_ready():
    logger.info(f'{client.user} has connected to Discord!')
    # Scan for unhandled requests
    try:
        asyncio.create_task(scan_unhandled_requests())
    except Exception as e:
        logger.error(f"Failed to start request scan: {e}")
    # Start periodic checks (first run happens after initial interval)
    if ENABLE_HEALTH_CHECKS:
        try:
            asyncio.create_task(periodic_health_checks_loop())
            logger.info(f"Health checks enabled (interval: {HEALTH_CHECK_INTERVAL}s)")
        except Exception as e:
            logger.error(f"Failed to start health check tasks: {e}")
    else:
        logger.info("Health checks disabled via ENABLE_HEALTH_CHECKS")


@client.event
async def on_message(message):
    # Ignore messages from the bot itself
    if message.author == client.user:
        return
    # Handle !close in temporary channels
    try:
        if isinstance(message.channel, discord.TextChannel) and is_temporary_channel(message.channel):
            content = message.content.strip().lower()
            if content == '!close':
                if not isinstance(message.author, discord.Member):
                    # Fetch member from guild if needed
                    author = message.guild.get_member(message.author.id) if message.guild else None
                else:
                    author = message.author
                if not author or not can_user_close_channel(author, message.channel):
                    await message.channel.send("You do not have permission to close this channel.")
                    return
                try:
                    await message.channel.send("Closing channel...")
                    await message.channel.delete(reason=f"Closed via !close by {message.author}")
                except Exception as e:
                    logger.error(f"Failed to close temporary channel: {e}")
                return
        else:
            content = message.content.strip().lower()
            if content == '!clear':
                # Confirmation flow
                try:
                    await message.channel.send("Are you sure you want to clear all messages in this channel?", view=ClearConfirmView())
                except Exception as e:
                    logger.error(f"Failed to present clear confirmation: {e}")
                return
    except Exception as e:
        logger.error(f"Error handling !close command: {e}")

    # Check if message is in the request channel
    if message.channel.id == REQUEST_CHANNEL_ID:
        # Extract username from message (assuming the message contains just the username)
        username = message.content.strip()
        
        # If this user has a previous invalid attempt, delete it now
        key = (message.channel.id, message.author.id)
        await _cleanup_entry_now(key)

        # Skip if already has checkmark (already processed)
        has_checkmark = any(str(reaction.emoji) == "✅" for reaction in message.reactions)
        if has_checkmark:
            return
        
        # Validate username format
        if not is_valid_minecraft_username(username):
            await message.add_reaction("❌")
            error_msg = await message.channel.send(
                f"Invalid username format. Minecraft usernames must be 3-16 characters, "
                f"containing only letters, numbers, and underscores."
            )
            # Schedule cleanup after 5 minutes or next message
            await _schedule_cleanup(key, user_msg=message, error_msg=error_msg, delay_seconds=300)
            return
        
        # Check with Mojang API (no reaction yet, just validation)
        exists, uuid, error = await check_mojang_username(username)
        
        if not exists:
            await message.add_reaction("❌")
            error_msg = await message.channel.send(
                f"Username `{username}` does not exist on Mojang servers. {error if error else ''}"
            )
            # Schedule cleanup after 5 minutes or next message
            await _schedule_cleanup(key, user_msg=message, error_msg=error_msg, delay_seconds=300)
            return
        
        # Username valid and exists - mark pending and forward to admin for approval
        # Don't add checkmark until admin approves
        
        # Create the view with approve/deny buttons
        view = WhitelistRequestView(username, request_message=message, request_user=message.author)
        
        # Create embed for admin channel
        embed = discord.Embed(
            title="Whitelist Request",
            description=f"New whitelist request received",
            color=discord.Color.blue()
        )
        embed.add_field(name="Username", value=username, inline=False)
        if uuid:
            embed.add_field(name="UUID", value=uuid, inline=False)
        embed.add_field(name="Requested by", value=message.author.mention, inline=False)
        embed.add_field(name="Channel", value=message.channel.mention, inline=False)
        
        # Send to admin channel
        admin_channel = client.get_channel(ADMIN_CHANNEL_ID)
        if admin_channel:
            # Add hourglass pending review
            try:
                await message.add_reaction("⏳")
            except Exception:
                pass
            await admin_channel.send(embed=embed, view=view)
        else:
            error_msg = f"Could not find admin channel with ID {ADMIN_CHANNEL_ID}"
            logger.error(error_msg)
            await message.channel.send(
                "Sorry, there was an error processing your whitelist request. "
                "Please contact an administrator."
            )


# Run the bot
if __name__ == "__main__":
    try:
        logger.info("Starting bot...")
        client.run(DISCORD_TOKEN, log_handler=None)
    except discord.LoginFailure:
        logger.error("Invalid token provided")
    except discord.HTTPException as e:
        logger.error(f"HTTP error occurred: {e}")
    except Exception as e:
        logger.error(f"Failed to start bot: {e}", exc_info=True)
