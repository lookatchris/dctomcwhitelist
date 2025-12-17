"""Discord UI Views and Modals."""

import discord
import logging
import asyncio
from typing import Optional
from config import (
    ADMIN_ROLE_ID,
    APPEAL_CATEGORY_ID,
    ARCHIVE_CATEGORY_ID,
    CONFIRM_TIMEOUT_SECONDS,
    SUPPORT_ROLE_ID,
    SUPPORT_NOTIFIER_ROLE_ID,
)
from utils import is_valid_minecraft_username, whitelist_add_sync

logger = logging.getLogger(__name__)


class AppealViewHelpers:
    """Helper methods for parsing and checking appeal channel permissions."""
    
    @staticmethod
    def _parse_id(topic: str | None, key: str) -> int | None:
        """Parse a numeric ID from channel topic."""
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
        """Parse a boolean value from channel topic."""
        if not topic:
            return False
        import re
        m = re.search(rf"{key}\s*:\s*(True|False)", topic, re.IGNORECASE)
        if m:
            return m.group(1).lower() == 'true'
        return False

    @staticmethod
    def _is_admin_or_denier(interaction: discord.Interaction) -> bool:
        """Check if user is admin or the denier of the appeal."""
        user = interaction.user
        guild = interaction.guild
        if not guild:
            return False
        denier_id = AppealViewHelpers._parse_id(
            getattr(interaction.channel, 'topic', None), 'denier'
        )
        if denier_id and user.id == denier_id:
            return True
        admin_role = guild.get_role(ADMIN_ROLE_ID)
        if admin_role and admin_role in getattr(user, 'roles', []):
            return True
        return False

    @staticmethod
    def _is_request_user(interaction: discord.Interaction) -> bool:
        """Check if user is the original requester."""
        uid = AppealViewHelpers._parse_id(
            getattr(interaction.channel, 'topic', None), 'user'
        )
        return uid is not None and interaction.user.id == uid


class WhitelistRequestView(discord.ui.View):
    """View for admin approval/denial of whitelist requests (stateless, persistent across restarts)."""
    
    def __init__(self):
        super().__init__(timeout=None)

    def _extract_username_from_embed(self, interaction: discord.Interaction) -> str | None:
        """Extract username from the message embed."""
        try:
            embed = interaction.message.embeds[0]
            for field in embed.fields:
                if field.name == "Username":
                    return field.value
        except (IndexError, AttributeError):
            pass
        return None

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.green, custom_id="whitelist_approve")
    async def approve_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        username = self._extract_username_from_embed(interaction)
        if not username:
            await interaction.response.send_message("Could not extract username from request.", ephemeral=True)
            return
        modal = ApprovalReasonModal(username, request_message=None, request_user=None)
        await interaction.response.send_modal(modal)

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.red, custom_id="whitelist_deny")
    async def deny_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        username = self._extract_username_from_embed(interaction)
        if not username:
            await interaction.response.send_message("Could not extract username from request.", ephemeral=True)
            return
        modal = DenialReasonModal(username, request_message=None, request_user=None, admin=interaction.user)
        await interaction.response.send_modal(modal)


class InvalidUsernameView(discord.ui.View):
    """View for invalid username notifications."""
    
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Acknowledge", style=discord.ButtonStyle.primary, custom_id="invalid_username_ack_button")
    async def ack_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await interaction.response.send_message(
                "⚠️ Acknowledging will close this channel. Please confirm.",
                ephemeral=True,
                view=ConfirmAcknowledgeView(appealable=False)
            )
        except Exception as e:
            logger.error(f"Failed to show acknowledge confirmation: {e}")


class NonAppealableView(discord.ui.View):
    """View for non-appealable denials."""
    
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Acknowledge", style=discord.ButtonStyle.primary, custom_id="non_appeal_ack_button")
    async def ack_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await interaction.response.send_message(
                "⚠️ Acknowledging will close this channel. Please confirm.",
                ephemeral=True,
                view=ConfirmAcknowledgeView(appealable=False)
            )
        except Exception as e:
            logger.error(f"Failed to show acknowledge confirmation: {e}")


class AppealableView(discord.ui.View):
    """View for appealable denials with acknowledge and close options."""
    
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Acknowledge", style=discord.ButtonStyle.primary, custom_id="appealable_ack_button")
    async def ack_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not AppealViewHelpers._is_request_user(interaction):
            await interaction.response.send_message("Only the requester can acknowledge this.", ephemeral=True)
            return
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


class WarningAcknowledgeView(discord.ui.View):
    """View for acknowledging warnings in temporary appeal channels."""
    
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Acknowledge Warning", style=discord.ButtonStyle.primary, custom_id="warning_ack_button")
    async def ack_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not AppealViewHelpers._is_request_user(interaction):
            await interaction.response.send_message("Only the warned user can acknowledge this.", ephemeral=True)
            return
        try:
            await interaction.response.send_message(
                "⚠️ Acknowledging will hide this channel from you and notify admins. They will then decide to close or archive it. Are you sure?",
                ephemeral=True,
                view=ConfirmWarningAcknowledgeView()
            )
        except Exception as e:
            logger.error(f"Failed to show warning acknowledge confirmation: {e}")

    @discord.ui.button(label="Archive Warning Appeal", style=discord.ButtonStyle.danger, custom_id="warning_close_button")
    async def close_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not AppealViewHelpers._is_admin_or_denier(interaction):
            await interaction.response.send_message("You do not have permission to close this appeal.", ephemeral=True)
            return
        try:
            guild = interaction.guild
            if not guild:
                await interaction.response.send_message("Cannot archive outside a guild context.", ephemeral=True)
                return

            archive_category = None
            if ARCHIVE_CATEGORY_ID:
                archive_category = guild.get_channel(ARCHIVE_CATEGORY_ID)
                if archive_category and not isinstance(archive_category, discord.CategoryChannel):
                    archive_category = None

            if not archive_category:
                await interaction.response.send_message("Archive category not configured or not found. Please set ARCHIVE_CATEGORY_ID.", ephemeral=True)
                return

            channel = interaction.channel
            topic = getattr(channel, 'topic', '') or ''
            warned_user_id = AppealViewHelpers._parse_id(topic, 'user')
            warned_member = guild.get_member(warned_user_id) if warned_user_id else None

            # Move to archive category
            await channel.edit(category=archive_category, reason=f"Warning appeal archived by {interaction.user}")

            # Tighten permissions: hide from warned user and default role, keep admins/bot
            await channel.set_permissions(guild.default_role, view_channel=False, send_messages=False)
            if warned_member:
                # Explicitly remove the warned user's access in archive
                await channel.set_permissions(warned_member, view_channel=False, send_messages=False)
            admin_role = guild.get_role(ADMIN_ROLE_ID)
            if admin_role:
                await channel.set_permissions(admin_role, view_channel=True, send_messages=True)
            await channel.set_permissions(interaction.client.user, view_channel=True, send_messages=True)

            await interaction.response.send_message(
                f"Warning appeal archived to {archive_category.name}. Channel remains for records.",
                ephemeral=True
            )
            try:
                await channel.send(
                    f"Archived by {interaction.user.mention}. This channel is now limited to the team; the warned user no longer has access.")
            except Exception:
                pass
        except Exception as e:
            logger.error(f"Failed to delete warning appeal channel: {e}")
            try:
                await interaction.followup.send(f"Failed to archive channel: {e}", ephemeral=True)
            except Exception:
                pass


class ConfirmWarningAcknowledgeView(discord.ui.View):
    """Confirmation view for acknowledging warnings."""
    
    def __init__(self):
        super().__init__(timeout=CONFIRM_TIMEOUT_SECONDS)

    @discord.ui.button(label="Yes, confirm!", style=discord.ButtonStyle.danger, custom_id="warn_ack_confirm")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not AppealViewHelpers._is_request_user(interaction):
            await interaction.response.send_message("Only the warned user can acknowledge.", ephemeral=True)
            return
        
        try:
            channel = interaction.channel
            user = interaction.user
            
            await channel.set_permissions(user, read_messages=False, reason="User acknowledged warning")
            
            admin_role = interaction.guild.get_role(ADMIN_ROLE_ID)
            if admin_role:
                await channel.send(f"{admin_role.mention} The user has acknowledged the warning and can no longer see this channel. You may close it when ready.")
            
            await interaction.response.send_message("You have acknowledged the warning. You can no longer see this channel.", ephemeral=True)
        except Exception as e:
            logger.error(f"Failed to hide channel from user: {e}")
            try:
                await interaction.response.send_message(f"Failed to update channel: {e}", ephemeral=True)
            except Exception:
                pass

    @discord.ui.button(label="No, keep open", style=discord.ButtonStyle.secondary, custom_id="warn_ack_cancel")
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message("Okay, keeping the warning channel open.", ephemeral=True)


class ConfirmAcknowledgeView(discord.ui.View):
    """Confirmation view for acknowledging appeals."""
    
    def __init__(self, appealable: bool = False):
        super().__init__(timeout=CONFIRM_TIMEOUT_SECONDS)
        self.appealable = appealable

    @discord.ui.button(label="Yes, confirm!", style=discord.ButtonStyle.danger, custom_id="appeal_ack_confirm")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not AppealViewHelpers._is_request_user(interaction):
            await interaction.response.send_message("Only the requester can close this appeal.", ephemeral=True)
            return
        
        if self.appealable:
            # Hide channel from user, notify admins
            try:
                channel = interaction.channel
                user = interaction.user
                
                await channel.set_permissions(user, read_messages=False, reason="User acknowledged appeal")
                
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


class ClearConfirmView(discord.ui.View):
    """Confirmation view for clearing channel messages."""
    
    def __init__(self):
        super().__init__(timeout=CONFIRM_TIMEOUT_SECONDS)

    def _authorized(self, interaction: discord.Interaction) -> bool:
        """Check if user has admin permissions or is bot owner."""
        from config import ADMIN_ROLE_IDS, OWNER_USER_ID
        
        # Bot owner always authorized
        if OWNER_USER_ID and interaction.user.id == OWNER_USER_ID:
            return True
        
        # Check if user has any admin role
        user_role_ids = {role.id for role in getattr(interaction.user, 'roles', [])}
        return any(admin_role_id in user_role_ids for admin_role_id in ADMIN_ROLE_IDS)

    @discord.ui.button(label="Yes, clear messages", style=discord.ButtonStyle.danger, custom_id="confirm_clear_yes")
    async def yes(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._authorized(interaction):
            await interaction.response.send_message("You do not have permission to clear this channel.", ephemeral=True)
            return
        try:
            await interaction.response.send_message("Clearing messages...", ephemeral=True)
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


class SupportLauncherView(discord.ui.View):
    """View shown in the support channel to let users create support cases."""

    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Create Support Case", style=discord.ButtonStyle.primary, custom_id="support_create_button")
    async def create_case(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            guild = interaction.guild
            if not guild:
                await interaction.response.send_message("Support cases can only be created inside a server.", ephemeral=True)
                return

            # Determine temp category (reuse APPEAL_CATEGORY_ID as temp category)
            category = None
            if APPEAL_CATEGORY_ID:
                cat = guild.get_channel(APPEAL_CATEGORY_ID)
                if isinstance(cat, discord.CategoryChannel):
                    category = cat

            # Name format: support-ddmm-username
            from datetime import datetime
            date_tag = datetime.utcnow().strftime("%d%m")
            channel_name = f"support-{date_tag}-{interaction.user.name}"

            # Create support case channel with topic including requester user id
            case_channel = await guild.create_text_channel(
                name=channel_name,
                topic=f"Support case | user: {interaction.user.id}",
                category=category
            )

            # Permissions: default hidden; user + support role + admin + notifier + bot have access
            await case_channel.set_permissions(guild.default_role, view_channel=False, send_messages=False)
            await case_channel.set_permissions(interaction.user, view_channel=True, send_messages=True)
            await case_channel.set_permissions(interaction.client.user, view_channel=True, send_messages=True)
            # Support role (if configured)
            support_role = guild.get_role(SUPPORT_ROLE_ID) if SUPPORT_ROLE_ID else None
            if support_role:
                await case_channel.set_permissions(support_role, view_channel=True, send_messages=True)
            # Admin role always allowed
            admin_role = guild.get_role(ADMIN_ROLE_ID)
            if admin_role:
                await case_channel.set_permissions(admin_role, view_channel=True, send_messages=True)
            # Notifier role (if configured)
            notifier_role = guild.get_role(SUPPORT_NOTIFIER_ROLE_ID) if SUPPORT_NOTIFIER_ROLE_ID else None
            if notifier_role:
                await case_channel.set_permissions(notifier_role, view_channel=True, send_messages=True)

            # Send initial message with close button
            embed = discord.Embed(
                title="Support Case",
                description=(
                    "Welcome to your support case. A member of the support/admin team will assist you here.\n\n"
                    "When you're satisfied with the outcome, click 'Close Support Case' below to finish."
                ),
                color=discord.Color.blue()
            )
            
            # Build mention string: include notifier role if configured
            mention_parts = [interaction.user.mention]
            if SUPPORT_NOTIFIER_ROLE_ID:
                notifier_role = guild.get_role(SUPPORT_NOTIFIER_ROLE_ID)
                if notifier_role:
                    mention_parts.append(notifier_role.mention)
            
            mentions = " ".join(mention_parts)
            await case_channel.send(f"{mentions}", embed=embed, view=SupportCaseView())

            await interaction.response.send_message(
                f"✅ Created support case: {case_channel.mention}", ephemeral=True
            )
        except Exception as e:
            logger.error(f"Failed to create support case: {e}")
            try:
                await interaction.response.send_message(f"Failed to create support case: {e}", ephemeral=True)
            except Exception:
                pass


class SupportCaseView(discord.ui.View):
    """View inside support case channels to allow requester to close the case."""

    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Close Support Case", style=discord.ButtonStyle.danger, custom_id="support_close_button")
    async def close_case(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Only the requester can close the case
        if not AppealViewHelpers._is_request_user(interaction):
            await interaction.response.send_message("Only the requester can close this support case.", ephemeral=True)
            return
        try:
            channel = interaction.channel
            guild = interaction.guild
            user = interaction.user
            if not guild:
                await interaction.response.send_message("Cannot close outside a guild.", ephemeral=True)
                return

            # Remove read access from user, keep admin/support teams
            await channel.set_permissions(user, view_channel=False, send_messages=False)

            await interaction.response.send_message("✅ You have closed this support case. You can no longer see this channel.", ephemeral=True)
            # Announce closure to the team in the channel
            try:
                await channel.send(f"📌 {user.mention} has closed this support case. Admins/support can continue to view this thread for records.")
            except Exception:
                pass
        except Exception as e:
            logger.error(f"Failed to close support case: {e}")
            try:
                await interaction.response.send_message(f"Failed to close: {e}", ephemeral=True)
            except Exception:
                pass


class ApprovalReasonModal(discord.ui.Modal, title="Approve Whitelist Request"):
    """Modal for approving whitelist requests."""
    
    reason = discord.ui.TextInput(
        label="Approval Reason (optional)",
        placeholder="Provide a reason for approval",
        required=False,
        max_length=200
    )

    def __init__(self, username: str, request_message=None, request_user=None):
        super().__init__()
        self.username = username
        self.request_message = request_message
        self.request_user = request_user

    async def on_submit(self, interaction: discord.Interaction):
        # Defer immediately to prevent interaction timeout
        await interaction.response.defer()
        
        try:
            if not is_valid_minecraft_username(self.username):
                await interaction.followup.send(
                    f"Invalid username format: {self.username}", 
                    ephemeral=True
                )
                return
            
            # Run RCON in executor to avoid blocking
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, whitelist_add_sync, self.username)
            logger.info(f"RCON Response: {response}")
            
            reason_text = str(self.reason) if self.reason else "No reason provided"
            
            embed = interaction.message.embeds[0]
            embed.color = discord.Color.green()
            embed.title = "Whitelist Request - Approved"
            embed.add_field(name="Status", value="✅ Approved", inline=False)
            embed.add_field(name="Approved by", value=interaction.user.mention, inline=False)
            embed.add_field(name="Reason", value=reason_text, inline=False)
            
            await interaction.message.edit(embed=embed, view=None)
            
            # Extract request message info from embed footer
            try:
                footer_text = interaction.message.embeds[0].footer.text
                if footer_text and footer_text.startswith("Request: "):
                    parts = footer_text.replace("Request: ", "").split("/")
                    if len(parts) == 2:
                        channel_id = int(parts[0])
                        message_id = int(parts[1])
                        
                        # Get the request message and add reactions
                        request_channel = interaction.client.get_channel(channel_id)
                        if request_channel:
                            try:
                                request_message = await request_channel.fetch_message(message_id)
                                await request_message.add_reaction("✅")
                                try:
                                    await request_message.remove_reaction("⏳", interaction.client.user)
                                except Exception:
                                    pass
                            except Exception as e:
                                logger.error(f"Failed to add checkmark to request message: {e}")
            except Exception as e:
                logger.warning(f"Failed to extract request message info: {e}")
            
            #await interaction.followup.send("✅ Whitelist request approved successfully!", ephemeral=True)
            
        except Exception as e:
            error_msg = f"Error connecting to RCON or executing command: {str(e)}"
            logger.error(f"RCON Error: {e}")
            try:
                await interaction.followup.send(error_msg, ephemeral=True)
            except:
                pass


class DenialReasonModal(discord.ui.Modal, title="Deny Whitelist Request"):
    """Modal for denying whitelist requests."""
    
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

    def __init__(self, username: str, request_message=None, request_user=None, admin=None):
        super().__init__()
        self.username = username
        self.request_message = request_message
        self.request_user = request_user
        self.admin = admin

    async def on_submit(self, interaction: discord.Interaction):
        # Defer immediately to prevent interaction timeout
        await interaction.response.defer()
        
        try:
            reason_text = str(self.reason) if self.reason else "No reason provided"
            appeal_raw = (str(self.appeal_allowed) or "yes").strip().lower()
            appeal_possible = appeal_raw in ("yes", "y", "true", "1", "✅", "allowed", "ok")
            
            embed = interaction.message.embeds[0]
            embed.color = discord.Color.red()
            embed.title = "Whitelist Request - Denied"
            embed.add_field(name="Status", value="❌ Denied", inline=False)
            embed.add_field(name="Denied by", value=interaction.user.mention, inline=False)
            embed.add_field(name="Reason", value=reason_text, inline=False)
            embed.add_field(name="Appeal", value=("✅ Possible" if appeal_possible else "❌ Not possible"), inline=False)
            
            await interaction.message.edit(embed=embed, view=None)
            
            # Extract request message info from embed footer
            request_message = None
            request_user = None
            try:
                footer_text = interaction.message.embeds[0].footer.text
                if footer_text and footer_text.startswith("Request: "):
                    parts = footer_text.replace("Request: ", "").split("/")
                    if len(parts) == 2:
                        channel_id = int(parts[0])
                        message_id = int(parts[1])
                        
                        # Get the request message
                        request_channel = interaction.client.get_channel(channel_id)
                        if request_channel:
                            try:
                                request_message = await request_channel.fetch_message(message_id)
                                request_user = request_message.author
                            except Exception as e:
                                logger.error(f"Failed to fetch request message: {e}")
            except Exception as e:
                logger.warning(f"Failed to extract request message info: {e}")
            
            if request_message:
                try:
                    await request_message.delete()
                    logger.info(f"Deleted request message for {self.username}")
                except Exception as e:
                    logger.error(f"Failed to delete request message: {e}")
            
            if request_user:
                try:
                    guild = interaction.guild
                    if guild:
                        category = None
                        if APPEAL_CATEGORY_ID:
                            category = guild.get_channel(APPEAL_CATEGORY_ID)
                            if category and not isinstance(category, discord.CategoryChannel):
                                logger.warning(f"APPEAL_CATEGORY_ID {APPEAL_CATEGORY_ID} is not a category channel")
                                category = None
                        
                        private_channel = await guild.create_text_channel(
                            name=f"appeal-{request_user.name}",
                            topic=f"Appeal channel for whitelist denial of {self.username} | denier: {interaction.user.id} | user: {request_user.id} | appeal: {appeal_possible}",
                            category=category
                        )
                        
                        await private_channel.set_permissions(guild.default_role, view_channel=False)
                        await private_channel.set_permissions(request_user, view_channel=True, send_messages=appeal_possible)
                        await private_channel.set_permissions(interaction.client.user, view_channel=True, send_messages=True)
                        await private_channel.set_permissions(interaction.user, view_channel=True, send_messages=True)
                        
                        admin_role = guild.get_role(ADMIN_ROLE_ID)
                        if admin_role:
                            await private_channel.set_permissions(admin_role, view_channel=True, send_messages=True)
                        
                        deny_embed = discord.Embed(
                            title="Whitelist Request - Denied",
                            description=f"Your whitelist request for `{self.username}` has been **denied**.",
                            color=discord.Color.red()
                        )
                        deny_embed.add_field(name="Reason", value=reason_text, inline=False)
                        if appeal_possible:
                            deny_embed.add_field(name="Next Steps", value=f"Appeal is possible, use this channel to discuss your appeal. Once you're done click Acknowledge to close this appeal.", inline=False)
                            view = AppealableView()
                            admin_status = "✅ Appeal channel created"
                        else:
                            deny_embed.add_field(name="Next Steps", value=f"Appeal is not possible. Please acknowledge to close this message.", inline=False)
                            view = NonAppealableView()
                            admin_status = "❌ Appeal not possible (read-only channel)"

                        await private_channel.send(f"{request_user.mention}", embed=deny_embed, view=view)
                        try:
                            embed.add_field(name="Appeal Channel", value=admin_status, inline=False)
                            await interaction.message.edit(embed=embed)
                        except Exception as e:
                            logger.warning(f"Failed to update admin message with appeal info: {e}")
                        logger.info(f"Created private appeal channel {private_channel.name} for {request_user}")
                except Exception as e:
                    logger.error(f"Failed to create private appeal channel: {e}")
            
        except Exception as e:
            await interaction.response.send_message(
                f"Error processing denial: {str(e)}", 
                ephemeral=True
            )
            logger.error(f"Denial Error: {e}")
