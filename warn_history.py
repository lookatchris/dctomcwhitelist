"""Warning history logging and retrieval system."""

import json
import os
import logging
from datetime import datetime
from typing import List, Dict, Any
from threading import Lock

logger = logging.getLogger(__name__)

HISTORY_FILE = "warn_history.json"
_file_lock = Lock()


def _load_history() -> List[Dict[str, Any]]:
    """Load warning history from file."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load warning history: {e}")
        return []


def _save_history(history: List[Dict[str, Any]]) -> None:
    """Save warning history to file."""
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Failed to save warning history: {e}")


def log_warn(
    user_id: int,
    user_name: str,
    guild_id: int,
    guild_name: str,
    admin_id: int,
    admin_name: str,
    reason: str,
    warning_level: int
) -> None:
    """Log a warn action to history."""
    with _file_lock:
        history = _load_history()
        entry = {
            "action": "warn",
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "user_name": user_name,
            "guild_id": guild_id,
            "guild_name": guild_name,
            "admin_id": admin_id,
            "admin_name": admin_name,
            "reason": reason,
            "warning_level": warning_level
        }
        history.append(entry)
        _save_history(history)
        logger.info(f"Logged warn for user {user_id} in guild {guild_id}: {reason}")


def log_unwarn(
    user_id: int,
    user_name: str,
    guild_id: int,
    guild_name: str,
    admin_id: int,
    admin_name: str,
    previous_level: int,
    new_level: int
) -> None:
    """Log an unwarn action to history."""
    with _file_lock:
        history = _load_history()
        entry = {
            "action": "unwarn",
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "user_name": user_name,
            "guild_id": guild_id,
            "guild_name": guild_name,
            "admin_id": admin_id,
            "admin_name": admin_name,
            "previous_level": previous_level,
            "new_level": new_level
        }
        history.append(entry)
        _save_history(history)
        logger.info(f"Logged unwarn for user {user_id} in guild {guild_id}: {previous_level} -> {new_level}")


def get_user_history(user_id: int, guild_id: int | None = None) -> List[Dict[str, Any]]:
    """Get warning history for a specific user, optionally filtered by guild."""
    with _file_lock:
        history = _load_history()
        user_history = [entry for entry in history if entry.get("user_id") == user_id]
        if guild_id is not None:
            user_history = [entry for entry in user_history if entry.get("guild_id") == guild_id]
        return user_history


def format_history_embed(user_history: List[Dict[str, Any]], user_name: str) -> Dict[str, Any]:
    """Format user warning history as an embed dictionary."""
    import discord
    
    if not user_history:
        return {
            "title": f"Warning History for {user_name}",
            "description": "No previous warnings on record.",
            "color": discord.Color.green().value
        }
    
    embed_data = {
        "title": f"Warning History for {user_name}",
        "description": f"Total entries: {len(user_history)}",
        "color": discord.Color.orange().value,
        "fields": []
    }
    
    # Show most recent entries (limit to 10 for embed size)
    recent_history = sorted(user_history, key=lambda x: x.get("timestamp", ""), reverse=True)[:10]
    
    for idx, entry in enumerate(recent_history, 1):
        action = entry.get("action", "unknown")
        timestamp = entry.get("timestamp", "unknown")
        admin_name = entry.get("admin_name", "unknown")
        
        # Format timestamp to be more readable
        try:
            dt = datetime.fromisoformat(timestamp)
            time_str = dt.strftime("%Y-%m-%d %H:%M UTC")
        except:
            time_str = timestamp
        
        if action == "warn":
            reason = entry.get("reason", "No reason provided")
            level = entry.get("warning_level", "?")
            field_value = f"**Action:** Warned (Level {level})\n**Reason:** {reason}\n**By:** {admin_name}\n**When:** {time_str}"
        elif action == "unwarn":
            prev_level = entry.get("previous_level", "?")
            new_level = entry.get("new_level", "?")
            field_value = f"**Action:** Unwarned ({prev_level} → {new_level})\n**By:** {admin_name}\n**When:** {time_str}"
        else:
            field_value = f"**Action:** {action}\n**When:** {time_str}"
        
        embed_data["fields"].append({
            "name": f"Entry #{len(user_history) - idx + 1}",
            "value": field_value,
            "inline": False
        })
    
    if len(user_history) > 10:
        embed_data["footer"] = {"text": f"Showing 10 most recent of {len(user_history)} total entries"}
    
    return embed_data
