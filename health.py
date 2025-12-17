"""Health check and diagnostic functionality."""

import discord
import asyncio
import logging
from config import REQUEST_CHANNEL_ID, ADMIN_CHANNEL_ID, HEALTH_CHECK_INTERVAL
from utils import _check_rcon_sync

logger = logging.getLogger(__name__)


async def perform_health_check(client: discord.Client) -> discord.Embed:
    """
    Run checks: guild presence, channel access, and RCON connectivity. 
    Returns a discord.Embed with results.
    """
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


async def send_health_report(client: discord.Client, target_channel=None):
    """Send a health report to a channel."""
    embed = await perform_health_check(client)
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


async def periodic_health_checks_loop(client: discord.Client):
    """Continuously run health checks at configured intervals."""
    while True:
        try:
            await send_health_report(client)
        except Exception as e:
            logger.error(f"Periodic health check error: {e}")
        await asyncio.sleep(HEALTH_CHECK_INTERVAL)
