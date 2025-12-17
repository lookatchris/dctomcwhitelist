"""Configuration and environment variable management."""

import os
import logging
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


def _load_int_env(key: str, default: int | None = None, required: bool = False) -> int:
    """Load and validate an integer environment variable."""
    value = os.getenv(key, str(default) if default is not None else None)
    if not value:
        if required:
            raise ValueError(f"{key} environment variable is required")
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a valid integer")


def _load_str_env(key: str, required: bool = False) -> str | None:
    """Load a string environment variable."""
    value = os.getenv(key)
    if not value and required:
        raise ValueError(f"{key} environment variable is required")
    return value


def _load_bool_env(key: str, default: bool = True) -> bool:
    """Load a boolean environment variable."""
    value = os.getenv(key, str(default)).lower()
    return value in ('true', '1', 'yes', 'on')


def _load_int_list_env(key: str, required: bool = False) -> list[int]:
    """Load a comma-separated list of integers from environment variable."""
    value = os.getenv(key, '')
    if not value:
        if required:
            raise ValueError(f"{key} environment variable is required")
        return []
    try:
        return [int(x.strip()) for x in value.split(',') if x.strip()]
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a comma-separated list of integers")


# Discord Configuration
DISCORD_TOKEN = _load_str_env('DISCORD_TOKEN', required=True)

# Request channels - support both single and multiple channels
_single_request_channel = os.getenv('REQUEST_CHANNEL_ID', '')
_multi_request_channels = os.getenv('REQUEST_CHANNEL_IDS', '')

if _multi_request_channels:
    # Use multiple channels if REQUEST_CHANNEL_IDS is set
    REQUEST_CHANNEL_IDS = _load_int_list_env('REQUEST_CHANNEL_IDS', required=True)
    REQUEST_CHANNEL_ID = REQUEST_CHANNEL_IDS[0] if REQUEST_CHANNEL_IDS else None  # Primary for backwards compatibility
elif _single_request_channel:
    # Fallback to single channel for backwards compatibility
    REQUEST_CHANNEL_ID = _load_int_env('REQUEST_CHANNEL_ID', required=True)
    REQUEST_CHANNEL_IDS = [REQUEST_CHANNEL_ID]
else:
    raise ValueError("REQUEST_CHANNEL_IDS or REQUEST_CHANNEL_ID environment variable is required")

ADMIN_CHANNEL_ID = _load_int_env('ADMIN_CHANNEL_ID', required=True)

# Admin roles - support both single and multiple roles
_single_admin_role = os.getenv('ADMIN_ROLE_ID', '')
_multi_admin_roles = os.getenv('ADMIN_ROLE_IDS', '')

if _multi_admin_roles:
    # Use multiple roles if ADMIN_ROLE_IDS is set
    ADMIN_ROLE_IDS = _load_int_list_env('ADMIN_ROLE_IDS', required=True)
    ADMIN_ROLE_ID = ADMIN_ROLE_IDS[0] if ADMIN_ROLE_IDS else None  # Primary for backwards compatibility
elif _single_admin_role:
    # Fallback to single role for backwards compatibility
    ADMIN_ROLE_ID = _load_int_env('ADMIN_ROLE_ID', required=True)
    ADMIN_ROLE_IDS = [ADMIN_ROLE_ID]
else:
    raise ValueError("ADMIN_ROLE_IDS or ADMIN_ROLE_ID environment variable is required")

# Support channel and role
SUPPORT_CHANNEL_ID = _load_int_env('SUPPORT_CHANNEL_ID', required=True)
# Optional support role; if not set, admin role will be used for permissions
SUPPORT_ROLE_ID = _load_int_env('SUPPORT_ROLE_ID', required=False)
# Optional role to notify/mention when support cases are created
SUPPORT_NOTIFIER_ROLE_ID = _load_int_env('SUPPORT_NOTIFIER_ROLE_ID', required=False)

# Owner Configuration - bot owner can always execute admin commands
OWNER_USER_ID = _load_int_env('OWNER_USER_ID', required=False)

APPEAL_CATEGORY_ID = _load_int_env('APPEAL_CATEGORY_ID', required=False)
ARCHIVE_CATEGORY_ID = _load_int_env('ARCHIVE_CATEGORY_ID', required=False)

# RCON Configuration
RCON_HOST = _load_str_env('RCON_HOST', required=True)
RCON_PORT = _load_int_env('RCON_PORT', default=25575)
RCON_PASSWORD = _load_str_env('RCON_PASSWORD', required=True)

# Health Check Configuration
HEALTH_CHECK_INTERVAL = _load_int_env('HEALTH_CHECK_INTERVAL', default=3600)
ENABLE_HEALTH_CHECKS = _load_bool_env('ENABLE_HEALTH_CHECKS', default=True)

# Debug Configuration
DEBUG = _load_bool_env('DEBUG', default=False)

# Presence / Status Configuration
# STATUS_TYPE: one of playing|listening|watching|competing|streaming
STATUS_TYPE = (os.getenv('STATUS_TYPE') or 'playing').strip().lower()
STATUS_TEXT = _load_str_env('STATUS_TEXT') or 'managing the Minecraft whitelist'
STATUS_STREAM_URL = _load_str_env('STATUS_STREAM_URL')  # optional, used when streaming

# Constants
MESSAGE_CLEANUP_DELAY_SECONDS = 300  # 5 minutes
CONFIRM_TIMEOUT_SECONDS = 60
    
# Warn roles (used by /warn and /unwarn)
WARN_ROLE_ID_1 = _load_int_env('WARN_ROLE_ID_1', required=True)
WARN_ROLE_ID_2 = _load_int_env('WARN_ROLE_ID_2', required=True)
