"""Discord Whitelist Bot - Main entry point."""

import discord
from discord import app_commands
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor

from config import (
    DISCORD_TOKEN,
    ADMIN_ROLE_ID,
    ADMIN_ROLE_IDS,
    OWNER_USER_ID,
    ADMIN_CHANNEL_ID,
    SUPPORT_CHANNEL_ID,
    SUPPORT_ROLE_ID,
    SUPPORT_NOTIFIER_ROLE_ID,
    ARCHIVE_CATEGORY_ID,
    APPEAL_CATEGORY_ID,
    REQUEST_CHANNEL_IDS,
    ENABLE_HEALTH_CHECKS,
    MESSAGE_CLEANUP_DELAY_SECONDS,
    DEBUG,
    RCON_HOST,
    RCON_PORT,
    STATUS_TYPE,
    STATUS_TEXT,
    STATUS_STREAM_URL,
    WARN_ROLE_ID_1,
    WARN_ROLE_ID_2,
)
from views import (
    InvalidUsernameView,
    NonAppealableView,
    AppealableView,
    ClearConfirmView,
    WhitelistRequestView,
    WarningAcknowledgeView,
    SupportLauncherView,
    SupportCaseView,
)
from health import periodic_health_checks_loop, perform_health_check
from handlers import (
    handle_whitelist_request,
    scan_unhandled_requests,
)
from appeal_channels import is_temporary_channel, can_user_close_channel
import warn_history

# Configure logging with file handlers
import os
from logging.handlers import RotatingFileHandler

# Create logs directory if it doesn't exist
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)

# Configure formatters
detailed_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Root logger configuration
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)

# Remove any existing handlers
root_logger.handlers.clear()

# Console handler (stdout)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG if DEBUG else logging.INFO)
console_handler.setFormatter(detailed_formatter)
root_logger.addHandler(console_handler)

# General log file (all logs, excluding debug if disabled)
general_handler = RotatingFileHandler(
    os.path.join(log_dir, "general.log"),
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
general_handler.setLevel(logging.DEBUG if DEBUG else logging.INFO)
general_handler.setFormatter(detailed_formatter)
root_logger.addHandler(general_handler)

# Info log file
info_handler = RotatingFileHandler(
    os.path.join(log_dir, "info.log"),
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
info_handler.setLevel(logging.INFO)
info_handler.setFormatter(detailed_formatter)
root_logger.addHandler(info_handler)

# Warning log file
warning_handler = RotatingFileHandler(
    os.path.join(log_dir, "warning.log"),
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
warning_handler.setLevel(logging.WARNING)
warning_handler.setFormatter(detailed_formatter)
root_logger.addHandler(warning_handler)

# Error log file
error_handler = RotatingFileHandler(
    os.path.join(log_dir, "error.log"),
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(detailed_formatter)
root_logger.addHandler(error_handler)

# Debug log file (only if DEBUG is enabled)
if DEBUG:
    debug_handler = RotatingFileHandler(
        os.path.join(log_dir, "debug.log"),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(debug_handler)

logger = logging.getLogger(__name__)
logger.info(f"Logging configured - DEBUG={'enabled' if DEBUG else 'disabled'}")

# Setup Discord intents
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True


def is_admin(interaction: discord.Interaction) -> bool:
    """Check if user is bot owner or has an admin role."""
    # Bot owner always has admin permissions
    if OWNER_USER_ID and interaction.user.id == OWNER_USER_ID:
        return True
    
    # Check if user has any admin role (only works in guilds with Member objects)
    if hasattr(interaction.user, 'roles'):
        user_role_ids = {role.id for role in interaction.user.roles}
        return any(admin_role_id in user_role_ids for admin_role_id in ADMIN_ROLE_IDS)
    
    return False


def has_admin_role():
    """Decorator to check admin permissions (owner or admin role)."""
    async def predicate(interaction: discord.Interaction) -> bool:
        if not is_admin(interaction):
            raise app_commands.MissingRole(ADMIN_ROLE_ID)
        return True
    
    return app_commands.check(predicate)


class MyClient(discord.Client):
    """Custom Discord client with command tree and thread executor."""
    
    def __init__(self, *, intents: discord.Intents):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.cleanup_map = {}  # Track cleanup tasks for invalid requests
        self.warn_map = {}     # Track warnings per user_id -> list of reasons


def _warning_level_from_roles(member: discord.Member) -> int:
    """Return warning level based on roles: 2 if WARN_ROLE_ID_2 present, 1 if WARN_ROLE_ID_1, else 0."""
    role_ids = {r.id for r in getattr(member, 'roles', [])}
    if WARN_ROLE_ID_2 in role_ids:
        return 2
    if WARN_ROLE_ID_1 in role_ids:
        return 1
    return 0

    async def setup_hook(self):
        """Called after client connects; syncs commands and registers persistent views."""
        try:
            synced = await self.tree.sync()
            logger.info(f"Command tree synced: {len(synced)} commands")
            for cmd in synced:
                logger.info(f"  - /{cmd.name}: {cmd.description}")
        except Exception as e:
            logger.error(f"Failed to sync command tree: {e}")
        
        # Register persistent views so buttons continue working after restarts
        # Only register views with timeout=None (truly persistent)
        try:
            self.add_view(InvalidUsernameView())
            self.add_view(NonAppealableView())
            self.add_view(AppealableView())
            self.add_view(WhitelistRequestView())
            self.add_view(WarningAcknowledgeView())
            self.add_view(SupportLauncherView())
            self.add_view(SupportCaseView())
            # Note: ConfirmAcknowledgeView, ConfirmWarningAcknowledgeView, and ClearConfirmView are ephemeral (have timeouts)
            # and should NOT be registered as persistent
            logger.info("Persistent views registered")
        except Exception as e:
            logger.error(f"Failed to register persistent views: {e}")


client = MyClient(intents=intents)


@client.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    """Handle errors from slash commands."""
    if isinstance(error, app_commands.MissingRole):
        # User doesn't have permission - send message and cleanup after delay
        try:
            # Send the error message
            error_msg = await interaction.response.send_message(
                f"❌ You do not have permission to run this command. Required role: <@&{ADMIN_ROLE_ID}>",
                ephemeral=False
            )
            
            # Delete the command message if possible
            try:
                await interaction.message.delete()
            except:
                pass  # Command message might be from interaction, not a regular message
            
            # Schedule deletion of the error message
            await asyncio.sleep(MESSAGE_CLEANUP_DELAY_SECONDS)
            try:
                await error_msg.delete()
            except:
                pass  # Message might have already been deleted
        except Exception as e:
            logger.error(f"Failed to handle MissingRole error: {e}")
    else:
        # Other errors - log and defer response if not already responded
        logger.error(f"Unhandled app command error: {error}", exc_info=error)
        if not interaction.response.is_done():
            try:
                await interaction.response.send_message(
                    "An error occurred while executing this command.",
                    ephemeral=True
                )
            except:
                pass



@client.tree.command(name="health", description="Run bot health checks")
@has_admin_role()
async def health_command(interaction: discord.Interaction):
    """Slash command to run health checks."""
    await interaction.response.defer(ephemeral=False)
    try:
        embed = await perform_health_check(client)
        await interaction.followup.send(embed=embed)
    except Exception as e:
        logger.error(f"Health command error: {e}")
        await interaction.followup.send(f"Error running health check: {e}", ephemeral=True)


@client.tree.command(name="close", description="Close the current appeal channel")
async def close_command(interaction: discord.Interaction):
    """Slash command to close temporary appeal channels."""
    await interaction.response.defer(ephemeral=True)
    
    if not isinstance(interaction.channel, discord.TextChannel):
        await interaction.followup.send("This command can only be used in text channels.", ephemeral=True)
        return
    
    if not is_temporary_channel(interaction.channel):
        await interaction.followup.send("This is not a temporary appeal channel.", ephemeral=True)
        return
    
    author = interaction.user
    if not isinstance(author, discord.Member):
        author = interaction.guild.get_member(author.id) if interaction.guild else None
    
    if not author or not can_user_close_channel(author, interaction.channel):
        await interaction.followup.send("You do not have permission to close this channel.", ephemeral=True)
        return
    
    try:
        await interaction.followup.send("Closing channel...")
        await interaction.channel.delete(reason=f"Closed via /close by {interaction.user}")
    except Exception as e:
        logger.error(f"Failed to close temporary channel: {e}")
        await interaction.followup.send(f"Failed to close channel: {e}", ephemeral=True)


@client.tree.command(name="clear", description="Clear all messages in the current channel")
@has_admin_role()
async def clear_command(interaction: discord.Interaction):
    """Slash command to clear messages in any channel (admin only)."""
    await interaction.response.defer(ephemeral=False)
    
    if not isinstance(interaction.channel, discord.TextChannel):
        await interaction.followup.send("This command can only be used in text channels.")
        return
    
    # Send confirmation view
    try:
        await interaction.followup.send(
            "Are you sure you want to clear all messages in this channel?",
            view=ClearConfirmView()
        )
    except Exception as e:
        logger.error(f"Failed to present clear confirmation: {e}")
        await interaction.followup.send(f"Failed to show confirmation: {e}", ephemeral=True)


@client.tree.command(name="ping", description="Test latency to Discord, RCON server, and internet")
async def ping_command(interaction: discord.Interaction):
    """Slash command to test connectivity and latency."""
    import time
    from utils import ping_rcon, ping_host
    
    # Measure Discord API latency (websocket heartbeat)
    discord_latency = client.latency * 1000  # Convert to ms
    
    await interaction.response.defer(ephemeral=False)
    
    # Create embed
    embed = discord.Embed(
        title="🏓 (Ping)Pong Test Results",
        color=discord.Color.blue()
    )
    
    # Discord WebSocket latency
    embed.add_field(
        name="Discord WebSocket",
        value=f"`{discord_latency:.2f}ms`",
        inline=False
    )
    
    # Test RCON server
    rcon_success, rcon_latency, rcon_error = await ping_rcon()
    if rcon_success and rcon_latency is not None:
        embed.add_field(
            # Removed RCON Server IP and port from name for Confidentiality
            name=f"RCON Server",
            value=f"✅ `{rcon_latency:.2f}ms`",
            inline=False
        )
    else:
        embed.add_field(
            # Removed RCON Server IP and port from name for Confidentiality
            name=f"RCON Server",
            value=f"❌ {rcon_error or 'Connection failed'}",
            inline=False
        )
    
    # Test 1.1.1.1 (Cloudflare DNS)
    internet_success, internet_latency, internet_error = await ping_host("1.1.1.1", 80, timeout=3.0)
    if internet_success and internet_latency is not None:
        embed.add_field(
            # Removed IP from name for Confidentiality
            name="Internet",
            value=f"✅ `{internet_latency:.2f}ms`",
            inline=False
        )
    else:
        embed.add_field(
            name="Internet",
            value=f"❌ {internet_error or 'Connection failed'}",
            inline=False
        )
    
    embed.set_footer(text=f"Requested by {interaction.user.display_name}")
    
    await interaction.followup.send(embed=embed)


@client.tree.command(name="info", description="Show bot configuration info")
@has_admin_role()
async def info_command(interaction: discord.Interaction):
    """Displays configured channels, roles, and owner."""
    await interaction.response.defer(ephemeral=True)
    try:
        guild = interaction.guild

        # Channels
        channel_mentions = []
        if guild:
            for cid in REQUEST_CHANNEL_IDS:
                ch = guild.get_channel(cid)
                channel_mentions.append(ch.mention if ch else f"`{cid}` (not found)")
            admin_channel = guild.get_channel(ADMIN_CHANNEL_ID)
            admin_ch_str = admin_channel.mention if admin_channel else f"`{ADMIN_CHANNEL_ID}` (not found)"
        else:
            channel_mentions = [f"`{cid}`" for cid in REQUEST_CHANNEL_IDS]
            admin_ch_str = f"`{ADMIN_CHANNEL_ID}`"

        # Roles
        role_mentions = []
        if guild:
            for rid in ADMIN_ROLE_IDS:
                r = guild.get_role(rid)
                role_mentions.append(r.mention if r else f"`{rid}` (not found)")
        else:
            role_mentions = [f"`{rid}`" for rid in ADMIN_ROLE_IDS]

        # Owner
        owner_str = "not configured"
        if OWNER_USER_ID:
            if guild:
                owner_member = guild.get_member(OWNER_USER_ID)
                if owner_member:
                    owner_str = owner_member.mention
                else:
                    # Fall back to user mention syntax even if not in guild; optionally fetch user
                    try:
                        user_obj = await client.fetch_user(OWNER_USER_ID)
                        owner_str = f"<@{OWNER_USER_ID}>"
                    except Exception:
                        owner_str = f"<@{OWNER_USER_ID}>"
            else:
                # No guild context; best effort mention
                owner_str = f"<@{OWNER_USER_ID}>"

        embed = discord.Embed(
            title="Bot Configuration Info",
            color=discord.Color.blurple()
        )
        embed.add_field(name="Request Channels", value="\n".join(channel_mentions) or "None", inline=False)
        embed.add_field(name="Admin Channel", value=admin_ch_str, inline=False)
        embed.add_field(name="Admin Roles", value="\n".join(role_mentions) or "None", inline=False)
        embed.add_field(name="Owner (user)", value=owner_str, inline=False)
        warn_role_1_str = "not configured"
        warn_role_2_str = "not configured"
        if WARN_ROLE_ID_1:
            if guild:
                warn_role_obj_1 = guild.get_role(WARN_ROLE_ID_1)
                warn_role_1_str = warn_role_obj_1.mention if warn_role_obj_1 else f"`{WARN_ROLE_ID_1}` (not found)"
            else:
                warn_role_1_str = f"`{WARN_ROLE_ID_1}`"
        if WARN_ROLE_ID_2:
            if guild:
                warn_role_obj_2 = guild.get_role(WARN_ROLE_ID_2)
                warn_role_2_str = warn_role_obj_2.mention if warn_role_obj_2 else f"`{WARN_ROLE_ID_2}` (not found)"
            else:
                warn_role_2_str = f"`{WARN_ROLE_ID_2}`"
        embed.add_field(name="Warn Role 1", value=warn_role_1_str, inline=False)
        embed.add_field(name="Warn Role 2", value=warn_role_2_str, inline=False)

        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Info command error: {e}")
        await interaction.followup.send(f"Failed to build info: {e}", ephemeral=True)


@client.tree.command(name="warn", description="Warn a user with a reason")
@has_admin_role()
async def warn_command(interaction: discord.Interaction, member: discord.Member, reason: str | None = None):
    """Warn a user (in-memory)."""
    await interaction.response.defer(ephemeral=True)
    status_msg = None
    try:
        status_msg = await interaction.followup.send("Processing warning...", ephemeral=True)
        warn_role_1 = interaction.guild.get_role(WARN_ROLE_ID_1) if interaction.guild else None
        warn_role_2 = interaction.guild.get_role(WARN_ROLE_ID_2) if interaction.guild else None

        reason_text = reason.strip() if reason else "No reason provided"
        warnings = client.warn_map.setdefault(member.id, [])
        warnings.append(reason_text)
        # Determine current warning level from roles to avoid relying on channels
        current_level = _warning_level_from_roles(member)
        if current_level >= 2:
            # Already at max level; escalate to manual admin review channel
            warn_count = 2
            response_lines = [
                f"⚠️ {member.mention} is already at the maximum warning level (2).",
                "A manual review channel will be created for admins to decide next steps.",
                f"Reason for additional warning attempt: {reason_text}"
            ]

            try:
                guild = interaction.guild
                if guild:
                    category = None
                    if APPEAL_CATEGORY_ID:
                        category = guild.get_channel(APPEAL_CATEGORY_ID)
                        if category and not isinstance(category, discord.CategoryChannel):
                            category = None

                    review_channel = await guild.create_text_channel(
                        name=f"warn-review-{member.name}",
                        topic=("Warning overflow review | user: "
                               f"{member.id} | admin: {interaction.user.id}"),
                        category=category
                    )

                    # Permissions: admin-only (no user access)
                    await review_channel.set_permissions(guild.default_role, view_channel=False)
                    await review_channel.set_permissions(member, view_channel=False, send_messages=False)
                    await review_channel.set_permissions(interaction.client.user, view_channel=True, send_messages=True)
                    await review_channel.set_permissions(interaction.user, view_channel=True, send_messages=True)
                    admin_role = guild.get_role(ADMIN_ROLE_ID)
                    if admin_role:
                        await review_channel.set_permissions(admin_role, view_channel=True, send_messages=True)

                    # Notify admins only (user cannot see this channel)
                    admin_mentions = []
                    for admin_role_id in ADMIN_ROLE_IDS:
                        role_obj = guild.get_role(admin_role_id)
                        if role_obj:
                            admin_mentions.append(role_obj.mention)

                    await review_channel.send(
                        f"{interaction.user.mention} {' '.join(admin_mentions)}\n"
                        f"**({member.name})** has exceeded the maximum warnings (2).\n"
                        f"Latest reason: {reason_text}\n\n"
                        f"This is an admin-only channel to discuss next steps."
                    )
                    # Log overflow warning attempt to history
                    try:
                        warn_history.log_warn(
                            user_id=member.id,
                            user_name=str(member),
                            guild_id=interaction.guild.id,
                            guild_name=interaction.guild.name,
                            admin_id=interaction.user.id,
                            admin_name=str(interaction.user),
                            reason=f"[OVERFLOW] {reason_text}",
                            warning_level=2  # Already at max
                        )
                    except Exception as hist_e:
                        logger.error(f"Failed to log overflow warning to history: {hist_e}")

                    # Post warning history in review channel
                    try:
                        user_history = warn_history.get_user_history(member.id, interaction.guild.id)
                        history_embed_data = warn_history.format_history_embed(user_history, str(member))
                        history_embed = discord.Embed.from_dict(history_embed_data)
                        await review_channel.send(embed=history_embed)
                    except Exception as hist_e:
                        logger.error(f"Failed to post warning history in review channel: {hist_e}")

                    response_lines.append(f"Review channel created: {review_channel.mention}")
            except Exception as overflow_e:
                logger.error(f"Failed to create warning overflow review channel: {overflow_e}")
                response_lines.append(f"⚠️ Failed to create review channel: {overflow_e}")

            final_text = "\n".join(response_lines)
            if status_msg:
                try:
                    await status_msg.edit(content=final_text)
                except Exception:
                    await interaction.followup.send(final_text, ephemeral=True)
            else:
                await interaction.followup.send(final_text, ephemeral=True)
            return

        warn_count = min(2, current_level + 1)
        # Ensure reasons list length is at least warn_count for display
        if len(warnings) < warn_count:
            # pad with placeholders if needed
            while len(warnings) < warn_count:
                warnings.append("(no reason recorded)")

        role_changes = []
        role_errors = []

        if warn_count >= 2:
            # Escalate to warning level 2
            if warn_role_2:
                if warn_role_2 not in member.roles:
                    try:
                        await member.add_roles(warn_role_2, reason=f"Warning level 2 by {interaction.user} ({reason_text})")
                        role_changes.append(f"Warn role 2 applied: {warn_role_2.mention}")
                    except Exception as role_exc:
                        logger.error(f"Failed to apply warn role 2: {role_exc}")
                        role_errors.append(f"Warn role 2 not applied: {role_exc}")
            else:
                role_errors.append(f"Warn role 2 with ID `{WARN_ROLE_ID_2}` not found in this server.")

            # Remove warn role 1 if still present to keep only the higher tier
            if warn_role_1 and warn_role_1 in member.roles:
                try:
                    await member.remove_roles(warn_role_1, reason=f"Replaced by warning level 2 for {member}")
                    role_changes.append("Warn role 1 removed (escalated to level 2).")
                except Exception as role_exc:
                    logger.error(f"Failed to remove warn role 1 during escalation: {role_exc}")
                    role_errors.append(f"Warn role 1 not removed during escalation: {role_exc}")
        else:
            # Warning level 1
            if warn_role_1:
                if warn_role_1 not in member.roles:
                    try:
                        await member.add_roles(warn_role_1, reason=f"Warning level 1 by {interaction.user} ({reason_text})")
                        role_changes.append(f"Warn role 1 applied: {warn_role_1.mention}")
                    except Exception as role_exc:
                        logger.error(f"Failed to apply warn role 1: {role_exc}")
                        role_errors.append(f"Warn role 1 not applied: {role_exc}")
            else:
                role_errors.append(f"Warn role 1 with ID `{WARN_ROLE_ID_1}` not found in this server.")

        response_lines = [
            f"⚠️ {member.mention} has been warned. Total warnings: {len(warnings)}",
            f"Reason: {reason_text}"
        ]
        response_lines.extend(role_changes)
        response_lines.extend(role_errors)

        # Log warning to history file
        try:
            warn_history.log_warn(
                user_id=member.id,
                user_name=str(member),
                guild_id=interaction.guild.id,
                guild_name=interaction.guild.name,
                admin_id=interaction.user.id,
                admin_name=str(interaction.user),
                reason=reason_text,
                warning_level=warn_count
            )
        except Exception as hist_e:
            logger.error(f"Failed to log warning to history: {hist_e}")

        # Create appeal channel for warning acknowledgment
        try:
            guild = interaction.guild
            if guild:
                category = None
                if APPEAL_CATEGORY_ID:
                    category = guild.get_channel(APPEAL_CATEGORY_ID)
                    if category and not isinstance(category, discord.CategoryChannel):
                        logger.warning(f"APPEAL_CATEGORY_ID {APPEAL_CATEGORY_ID} is not a category channel")
                        category = None
                
                # Create warning appeal channel
                warn_appeal_channel = await guild.create_text_channel(
                    name=f"warn-{member.name}",
                    topic=f"Warning appeal channel for {member.name} | admin: {interaction.user.id} | user: {member.id} | level: {len(warnings)}",
                    category=category
                )
                
                # Set permissions: user can read, admins can write, others hidden
                await warn_appeal_channel.set_permissions(guild.default_role, view_channel=False)
                await warn_appeal_channel.set_permissions(member, view_channel=True, send_messages=True)
                await warn_appeal_channel.set_permissions(interaction.client.user, view_channel=True, send_messages=True)
                await warn_appeal_channel.set_permissions(interaction.user, view_channel=True, send_messages=True)
                
                admin_role = guild.get_role(ADMIN_ROLE_ID)
                if admin_role:
                    await warn_appeal_channel.set_permissions(admin_role, view_channel=True, send_messages=True)
                
                # Create warning notification embed
                warn_embed = discord.Embed(
                    title=f"Warning Level {len(warnings)}",
                    description=f"You have been warned in {guild.name}.",
                    color=discord.Color.orange()
                )
                warn_embed.add_field(name="Reason", value=reason_text, inline=False)
                warn_embed.add_field(name="Total Warnings", value=str(len(warnings)), inline=False)
                warn_embed.add_field(name="Warned by", value=interaction.user.mention, inline=False)
                if len(warnings) == 1:
                    warn_embed.add_field(
                        name="Next Steps",
                        value=f"You may discuss your warning with the admins here. Afterwards, please acknowledge this warning by clicking the button below. After acknowledgment, you will lose read access to this channel and admins can archive it.",
                        inline=False
                    )
                else:
                    warn_embed.add_field(
                        name="Next Steps",
                        value=f"You may discuss your warning with the admins here. Afterwards, please acknowledge this warning by clicking the button below. After acknowledgment, you will lose read access to this channel and admins can archive it.",
                        inline=False
                    )
                
                await warn_appeal_channel.send(f"{member.mention}", embed=warn_embed, view=WarningAcknowledgeView())
                
                # Send notification to admins and delete it after they see it
                admin_mentions = []
                for admin_role_id in ADMIN_ROLE_IDS:
                    admin_role = guild.get_role(admin_role_id)
                    if admin_role:
                        admin_mentions.append(admin_role.mention)
                
                notif_msg = await warn_appeal_channel.send(
                    f"{interaction.user.mention}",
                    delete_after=2  # Auto-delete after 2 seconds
                )
                
                response_lines.append(f"Warning appeal channel created: {warn_appeal_channel.mention}")
                logger.info(f"Created warning appeal channel {warn_appeal_channel.name} for {member}")
        except Exception as appeal_e:
            logger.error(f"Failed to create warning appeal channel: {appeal_e}")
            response_lines.append(f"⚠️ Warning appeal channel creation failed: {appeal_e}")

        final_text = "\n".join(response_lines)
        if status_msg:
            try:
                await status_msg.edit(content=final_text)
            except Exception:
                await interaction.followup.send(final_text, ephemeral=True)
        else:
            await interaction.followup.send(final_text, ephemeral=True)
        # try:
        #     await member.send(f"You have been warned in {interaction.guild.name}: {reason_text}\n\nA warning appeal channel has been created for you to acknowledge the warning.")
        # except Exception:
        #     pass
    except Exception as e:
        logger.error(f"Warn command error: {e}")
        fail_text = f"Failed to warn: {e}"
        if status_msg:
            try:
                await status_msg.edit(content=fail_text)
            except Exception:
                await interaction.followup.send(fail_text, ephemeral=True)
        else:
            await interaction.followup.send(fail_text, ephemeral=True)


@client.tree.command(name="unwarn", description="Remove the most recent warning from a user")
@has_admin_role()
async def unwarn_command(interaction: discord.Interaction, member: discord.Member):
    """Remove the latest warning (in-memory). Alternative name: /clearwarn."""
    await interaction.response.defer(ephemeral=True)
    try:
        warn_role_1 = interaction.guild.get_role(WARN_ROLE_ID_1) if interaction.guild else None
        warn_role_2 = interaction.guild.get_role(WARN_ROLE_ID_2) if interaction.guild else None
        warnings = client.warn_map.get(member.id, [])
        current_level = _warning_level_from_roles(member)
        if current_level == 0 and not warnings:
            await interaction.followup.send(f"{member.mention} has no warnings to remove.", ephemeral=True)
            return

        # Derive new level based on roles, decrement by one
        new_level = max(current_level - 1, 0)

        removed = "(no reason recorded)"
        if warnings:
            removed = warnings.pop()
        if new_level == 0:
            client.warn_map.pop(member.id, None)
        else:
            # Trim reasons to new_level
            warnings = warnings[:new_level]
            client.warn_map[member.id] = warnings
        warn_count = new_level

        role_changes = []
        role_errors = []

        if warn_count == 0:
            # Clear all warn roles
            for role_obj, role_label in ((warn_role_1, "Warn role 1"), (warn_role_2, "Warn role 2")):
                if role_obj and role_obj in member.roles:
                    try:
                        await member.remove_roles(role_obj, reason=f"Warnings cleared by {interaction.user}")
                        role_changes.append(f"{role_label} removed.")
                    except Exception as role_exc:
                        logger.error(f"Failed to remove {role_label.lower()}: {role_exc}")
                        role_errors.append(f"{role_label} not removed: {role_exc}")
        elif warn_count == 1:
            # Should have warn role 1 only
            if warn_role_2 and warn_role_2 in member.roles:
                try:
                    await member.remove_roles(warn_role_2, reason=f"Demoted to warning level 1 by {interaction.user}")
                    role_changes.append("Warn role 2 removed (demoted to level 1).")
                except Exception as role_exc:
                    logger.error(f"Failed to remove warn role 2 during demotion: {role_exc}")
                    role_errors.append(f"Warn role 2 not removed during demotion: {role_exc}")
            if warn_role_1 and warn_role_1 not in member.roles:
                try:
                    await member.add_roles(warn_role_1, reason=f"Warning level 1 by {interaction.user}")
                    role_changes.append(f"Warn role 1 applied: {warn_role_1.mention}")
                except Exception as role_exc:
                    logger.error(f"Failed to apply warn role 1 after demotion: {role_exc}")
                    role_errors.append(f"Warn role 1 not applied after demotion: {role_exc}")
        else:
            # warn_count >= 2 => ensure level 2 role present
            if warn_role_2 and warn_role_2 not in member.roles:
                try:
                    await member.add_roles(warn_role_2, reason=f"Warning level 2 by {interaction.user}")
                    role_changes.append(f"Warn role 2 applied: {warn_role_2.mention}")
                except Exception as role_exc:
                    logger.error(f"Failed to apply warn role 2 after unwarn: {role_exc}")
                    role_errors.append(f"Warn role 2 not applied after unwarn: {role_exc}")
            if warn_role_1 and warn_role_1 in member.roles:
                try:
                    await member.remove_roles(warn_role_1, reason=f"Warning level 2 retains only higher tier for {member}")
                    role_changes.append("Warn role 1 removed (level 2 retained).")
                except Exception as role_exc:
                    logger.error(f"Failed to remove warn role 1 while retaining level 2: {role_exc}")
                    role_errors.append(f"Warn role 1 not removed while retaining level 2: {role_exc}")

        response_lines = [
            f"✅ Removed latest warning for {member.mention}. Remaining warnings: {len(warnings)}",
            f"Removed: {removed}"
        ]
        response_lines.extend(role_changes)
        response_lines.extend(role_errors)

        # Log unwarn to history file
        try:
            warn_history.log_unwarn(
                user_id=member.id,
                user_name=str(member),
                guild_id=interaction.guild.id,
                guild_name=interaction.guild.name,
                admin_id=interaction.user.id,
                admin_name=str(interaction.user),
                previous_level=current_level,
                new_level=new_level
            )
        except Exception as hist_e:
            logger.error(f"Failed to log unwarn to history: {hist_e}")

        await interaction.followup.send("\n".join(response_lines), ephemeral=True)
    except Exception as e:
        logger.error(f"Unwarn command error: {e}")
        await interaction.followup.send(f"Failed to unwarn: {e}", ephemeral=True)


@client.tree.command(name="warnings", description="Show warnings for a user")
@has_admin_role()
async def warnings_command(interaction: discord.Interaction, member: discord.Member):
    """Show current warnings and reasons for a user."""
    await interaction.response.defer(ephemeral=True)
    try:
        role_level = _warning_level_from_roles(member)
        if role_level == 0:
            await interaction.followup.send(f"{member.mention} has no warnings.", ephemeral=True)
            return

        # Get warning history from file to display with timestamps
        user_history = warn_history.get_user_history(member.id, interaction.guild.id)
        warn_entries = [entry for entry in user_history if entry.get("action") == "warn"]
        
        embed = discord.Embed(
            title=f"Warnings for {member.display_name}",
            color=discord.Color.orange()
        )
        embed.add_field(name="Current Warning Level", value=str(role_level), inline=False)
        
        # Show most recent warnings up to current level
        recent_warns = sorted(warn_entries, key=lambda x: x.get("timestamp", ""), reverse=True)[:role_level]
        recent_warns.reverse()  # Show oldest to newest
        
        for idx, entry in enumerate(recent_warns, start=1):
            reason = entry.get("reason", "No reason provided")
            timestamp = entry.get("timestamp", "unknown")
            admin_name = entry.get("admin_name", "unknown")
            
            # Format timestamp
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime("%Y-%m-%d %H:%M UTC")
            except:
                time_str = timestamp
            
            field_value = f"**Reason:** {reason}\n**By:** {admin_name}\n**When:** {time_str}"
            embed.add_field(name=f"Warning {idx}", value=field_value, inline=False)
        
        # If we don't have enough history entries, note that
        if len(recent_warns) < role_level:
            embed.set_footer(text=f"Note: Only {len(recent_warns)} of {role_level} warnings have detailed history")

        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Warnings command error: {e}")
        await interaction.followup.send(f"Failed to fetch warnings: {e}", ephemeral=True)


@client.event
async def on_ready():
    """Called when the bot connects to Discord."""
    logger.info(f'{client.user} has connected to Discord!')
    
    # Set presence/activity based on configuration
    try:
        activity = None
        stype = STATUS_TYPE
        text = STATUS_TEXT
        if stype == 'playing':
            activity = discord.Game(name=text)
        elif stype == 'listening':
            activity = discord.Activity(type=discord.ActivityType.listening, name=text)
        elif stype == 'watching':
            activity = discord.Activity(type=discord.ActivityType.watching, name=text)
        elif stype == 'competing':
            activity = discord.Activity(type=discord.ActivityType.competing, name=text)
        elif stype == 'streaming' and STATUS_STREAM_URL:
            activity = discord.Streaming(name=text, url=STATUS_STREAM_URL)
        else:
            # Fallback to playing if invalid type
            activity = discord.Game(name=text)
            if stype not in ('playing','listening','watching','competing','streaming'):
                logger.warning(f"Unknown STATUS_TYPE '{stype}', defaulting to 'playing'")
        await client.change_presence(activity=activity)
        logger.info(f"Presence set: {stype} '{text}'")
    except Exception as e:
        logger.error(f"Failed to set presence: {e}")
    
    # Scan for unhandled requests
    try:
        asyncio.create_task(scan_unhandled_requests(client, client.executor))
    except Exception as e:
        logger.error(f"Failed to start request scan: {e}")
    
    # Start periodic checks if enabled
    if ENABLE_HEALTH_CHECKS:
        try:
            asyncio.create_task(periodic_health_checks_loop(client))
            logger.info(f"Health checks enabled")
        except Exception as e:
            logger.error(f"Failed to start health check tasks: {e}")
    else:
        logger.info("Health checks disabled via ENABLE_HEALTH_CHECKS")

    # Ensure Support Center launcher message exists; recreate if missing
    try:
        support_channel = client.get_channel(SUPPORT_CHANNEL_ID) if SUPPORT_CHANNEL_ID else None
        if support_channel and isinstance(support_channel, discord.TextChannel):
            exists = False
            launcher_msg = None
            try:
                async for msg in support_channel.history(limit=50):
                    if msg.author.id == client.user.id and msg.embeds:
                        for emb in msg.embeds:
                            if emb.title == "Support Center":
                                exists = True
                                launcher_msg = msg
                                break
                    if exists:
                        break
            except Exception as hist_e:
                logger.warning(f"Failed to check existing Support Center message: {hist_e}")

            if not exists:
                embed = discord.Embed(
                    title="Support Center",
                    description=(
                        "Need help? Create a support case to chat with the team.\nWe will reach out within 24 hours.\n\n"
                        "Click the button below to open a temporary support channel for you."
                    ),
                    color=discord.Color.blue()
                )
                await support_channel.send(embed=embed, view=SupportLauncherView())
                logger.info("Posted Support Center launcher in support channel (created).")
            else:
                # Re-attach view to existing message to ensure buttons work after restart
                if launcher_msg:
                    try:
                        await launcher_msg.edit(view=SupportLauncherView())
                        logger.info("Support Center launcher already present; re-attached view.")
                    except Exception as e:
                        logger.warning(f"Failed to re-attach SupportLauncherView: {e}")
        else:
            logger.warning("SUPPORT_CHANNEL_ID is not configured or not a text channel.")
    except Exception as e:
        logger.error(f"Failed to ensure Support Center launcher: {e}")
    
    # Re-attach SupportCaseView to existing support case messages for button persistence
    # This ensures buttons work even if the bot was restarted after cases were created
    try:
        for guild in client.guilds:
            for channel in guild.text_channels:
                # Only check channels named support-* (support cases)
                if channel.name.startswith("support-") and not channel.name.startswith("support-ddmm"):
                    try:
                        async for msg in channel.history(limit=10):
                            if msg.author.id == client.user.id and msg.embeds:
                                for emb in msg.embeds:
                                    if emb.title == "Support Case":
                                        # Re-attach the view to this message
                                        await msg.edit(view=SupportCaseView())
                                        logger.debug(f"Re-attached SupportCaseView to message in {channel.name}")
                                        break
                    except Exception as ch_e:
                        pass  # Silently skip channels with permission issues
    except Exception as e:
        logger.debug(f"Failed to re-attach support case views: {e}")


@client.event
async def on_message(message: discord.Message):
    """Handle incoming messages."""
    # Ignore messages from the bot itself
    if message.author == client.user:
        return
    
    # Debug logging
    logger.debug(f"Message received from {message.author}: {message.content}")
    
    # Handle whitelist requests in request channels
    if message.channel.id in REQUEST_CHANNEL_IDS:
        logger.debug(f"Request channel detected: {message.channel.id}")
        await handle_whitelist_request(message, client, client.cleanup_map, client.executor)


def run():
    """Start the Discord bot."""
    try:
        logger.info("Starting bot...")
        client.run(DISCORD_TOKEN, log_handler=None)
    except discord.LoginFailure:
        logger.error("Invalid token provided")
    except discord.HTTPException as e:
        logger.error(f"HTTP error occurred: {e}")
    except Exception as e:
        logger.error(f"Failed to start bot: {e}", exc_info=True)


if __name__ == "__main__":
    run()
