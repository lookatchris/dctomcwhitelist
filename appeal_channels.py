"""Appeal channel and temporary channel management."""

import discord
import logging
from config import ADMIN_ROLE_ID, APPEAL_CATEGORY_ID

logger = logging.getLogger(__name__)


def is_temporary_channel(channel: discord.abc.GuildChannel) -> bool:
    """Check if a channel is a temporary appeal/notification channel."""
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
        'Invalid username notification' in topic or
        'Warning appeal channel' in topic
    )


def can_user_close_channel(user: discord.Member, channel: discord.abc.GuildChannel) -> bool:
    """
    Check if a user can close a temporary channel.
    Admins can always close. For appeal channels, the denier can also close.
    For warning channels, the admin who issued the warning can also close.
    """
    guild = user.guild
    if not guild:
        return False
    
    admin_role = guild.get_role(ADMIN_ROLE_ID)
    if admin_role and admin_role in getattr(user, 'roles', []):
        return True
    
    # Check denier for appeal channels
    topic = getattr(channel, 'topic', '') or ''
    if 'Appeal channel for whitelist denial' in topic:
        from views import AppealViewHelpers
        denier_id = AppealViewHelpers._parse_id(topic, 'denier')
        if denier_id and user.id == denier_id:
            return True
    
    # Check admin for warning channels
    if 'Warning appeal channel' in topic:
        from views import AppealViewHelpers
        admin_id = AppealViewHelpers._parse_id(topic, 'admin')
        if admin_id and user.id == admin_id:
            return True
    
    return False


async def delete_message_safe(msg: discord.Message):
    """Safely delete a message with error handling."""
    try:
        await msg.delete()
    except Exception as e:
        logger.warning(f"Failed to delete message {getattr(msg, 'id', None)}: {e}")


async def cleanup_invalid_entry_now(cleanup_map: dict, key: tuple):
    """Immediately clean up an invalid username entry."""
    entry = cleanup_map.get(key)
    if not entry:
        return
    task = entry.get('task')
    if task and not task.done():
        try:
            task.cancel()
        except Exception:
            pass
    
    for m in [entry.get('user_msg'), entry.get('error_msg')]:
        if m:
            await delete_message_safe(m)
    
    cleanup_map.pop(key, None)


async def schedule_cleanup(cleanup_map: dict, key: tuple, user_msg: discord.Message, 
                          error_msg: discord.Message, delay_seconds: int = 300):
    """Schedule cleanup of invalid username messages."""
    import asyncio
    
    await cleanup_invalid_entry_now(cleanup_map, key)
    
    async def _runner():
        try:
            await asyncio.sleep(delay_seconds)
            await delete_message_safe(user_msg)
            await delete_message_safe(error_msg)
        finally:
            cleanup_map.pop(key, None)
    
    task = asyncio.create_task(_runner())
    cleanup_map[key] = {'user_msg': user_msg, 'error_msg': error_msg, 'task': task}


async def delete_channel_after(channel: discord.TextChannel, delay_seconds: int):
    """Delete a channel after a delay."""
    import asyncio
    try:
        await asyncio.sleep(delay_seconds)
        await channel.delete(reason=f"Auto-cleanup after {delay_seconds} seconds")
    except Exception as e:
        logger.warning(f"Auto-delete appeal channel failed: {e}")
