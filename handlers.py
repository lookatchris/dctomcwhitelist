"""Message handlers for whitelist requests and appeal interactions."""

import discord
import logging
import asyncio
from config import REQUEST_CHANNEL_IDS, ADMIN_CHANNEL_ID, APPEAL_CATEGORY_ID
from utils import (
    is_valid_minecraft_username,
    check_mojang_username,
    check_if_whitelisted,
)
from views import WhitelistRequestView, InvalidUsernameView
from appeal_channels import (
    is_temporary_channel,
    can_user_close_channel,
    cleanup_invalid_entry_now,
    schedule_cleanup,
)

logger = logging.getLogger(__name__)


async def handle_close_command(message: discord.Message):
    """Handle !close command in temporary channels."""
    if not isinstance(message.channel, discord.TextChannel):
        return
    
    if not is_temporary_channel(message.channel):
        return
    
    author = message.author
    if not isinstance(author, discord.Member):
        author = message.guild.get_member(author.id) if message.guild else None
    
    if not author or not can_user_close_channel(author, message.channel):
        await message.channel.send("You do not have permission to close this channel.")
        return
    
    try:
        await message.channel.send("Closing channel...")
        await message.channel.delete(reason=f"Closed via !close by {message.author}")
    except Exception as e:
        logger.error(f"Failed to close temporary channel: {e}")


async def handle_whitelist_request(message: discord.Message, client: discord.Client, cleanup_map: dict, executor):
    """
    Process a whitelist request from the request channel.
    Validates the username and forwards to admin channel.
    """
    username = message.content.strip()
    
    # Clean up any previous invalid attempts from this user
    key = (message.channel.id, message.author.id)
    await cleanup_invalid_entry_now(cleanup_map, key)

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
        await schedule_cleanup(cleanup_map, key, user_msg=message, error_msg=error_msg, delay_seconds=300)
        return
    
    # Check with Mojang API (no reaction yet, just validation)
    exists, uuid, error = await check_mojang_username(username)
    
    if not exists:
        await message.add_reaction("❌")
        error_msg = await message.channel.send(
            f"Username `{username}` does not exist on Mojang servers. {error if error else ''}"
        )
        await schedule_cleanup(cleanup_map, key, user_msg=message, error_msg=error_msg, delay_seconds=300)
        return
    
    # Username valid and exists - mark pending and forward to admin for approval
    view = WhitelistRequestView()
    
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
    
    # Store request message info in footer for later retrieval
    embed.set_footer(text=f"Request: {message.channel.id}/{message.id}")
    
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


async def scan_unhandled_requests(client: discord.Client, executor):
    """
    Scan all request channels for unhandled messages on startup.
    Recovers requests that didn't get processed before the bot restarted.
    """
    logger.info(f"Scanning {len(REQUEST_CHANNEL_IDS)} request channel(s) for unhandled messages...")
    
    for req_channel_id in REQUEST_CHANNEL_IDS:
        try:
            req_channel = client.get_channel(req_channel_id)
            if not req_channel:
                logger.error(f"Cannot scan: request channel {req_channel_id} not found")
                continue
            
            logger.info(f"Scanning request channel {req_channel.name} ({req_channel_id})...")
            
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
                is_whitelisted, error = await check_if_whitelisted(username, executor)
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
                            
                            from config import ADMIN_ROLE_ID
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
                            notif_embed.add_field(
                                name="Action",
                                value="Please verify the username spelling and re-request the whitelist in the request channel. This channel will be deleted after you acknowledge.",
                                inline=False
                            )
                            
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
                
                view = WhitelistRequestView()
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
                
                # Store request message info in footer for later retrieval
                embed.set_footer(text=f"Request: {message.channel.id}/{message.id}")
                
                admin_channel = client.get_channel(ADMIN_CHANNEL_ID)
                if admin_channel:
                    await admin_channel.send(embed=embed, view=view)
            
            logger.info(f"Scan complete for request channel {req_channel.name}")
        except Exception as e:
            logger.error(f"Error scanning request channel {req_channel_id}: {e}", exc_info=True)
    
    logger.info("All request channels scanned")
