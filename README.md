# dctomcwhitelist
Discord Bot which interacts with a Minecraft Server

## Quick Start

### Prerequisites
- Python 3.8 or higher
- A Discord bot token ([Create a bot](https://discord.com/developers/applications))
- Minecraft server with RCON enabled

### Setup Instructions

1. **Clone the repository:**
```bash
git clone https://github.com/lookatchris/dctomcwhitelist.git
cd dctomcwhitelist
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure environment variables:**
   - Copy `.env.example` to `.env`
   - Fill in your configuration:

```env
# Discord Bot Token
DISCORD_TOKEN=your_discord_bot_token_here

# Minecraft RCON Configuration
RCON_HOST=your_minecraft_server_ip
RCON_PORT=25575
RCON_PASSWORD=your_rcon_password

# Discord Channel IDs
REQUEST_CHANNEL_IDS=123456789012345678
ADMIN_CHANNEL_ID=123456789012345678
SUPPORT_CHANNEL_ID=
ARCHIVE_CATEGORY_ID=
APPEAL_CATEGORY_ID=

# Role IDs
ADMIN_ROLE_ID=111111111111111111
SUPPORT_ROLE_ID=
SUPPORT_NOTIFIER_ROLE_ID=
WARN_ROLE_ID_1=333333333333333333
WARN_ROLE_ID_2=444444444444444444

# Settings
ENABLE_HEALTH_CHECKS=false
DEBUG=false
OWNER_USER_ID=

# Presence / Status
STATUS_TYPE=Playing
STATUS_TEXT=Minecraft
```

4. **Get Discord Channel IDs:**
   - Enable Developer Mode in Discord (User Settings > Advanced > Developer Mode)
   - Right-click on a channel and select "Copy ID"

5. **Run the bot:**
```bash
python bot.py
```

## Features

- **Automated Whitelist Requests**: Users submit their Minecraft username in a request channel
- **Admin Approval System**: Admins receive formatted requests with Approve/Deny buttons
- **RCON Integration**: Approved requests automatically whitelist users on the Minecraft server
- **Input Validation**: Validates Minecraft username format to prevent command injection
- **Error Handling**: Comprehensive error handling for RCON connections and invalid inputs
- **Logging**: Detailed logging for debugging and monitoring
- **Warning System**: Track user violations with automatic role assignments at different warning levels
- **Multi-Channel Support**: Handle requests across multiple Discord channels

## Usage

1. **Submit a Whitelist Request**: Users post their Minecraft username in the request channel
2. **Review Requests**: Admins see formatted requests in the admin channel with Approve/Deny buttons
3. **Process Request**: Click Approve to whitelist the user or Deny to reject the request
4. **Confirmation**: The embed updates to show the approval/denial status and who processed it

## Security Features
- Environment variable validation on startup
- Minecraft username format validation (3-16 alphanumeric characters and underscores)
- Command injection prevention
- Secure RCON connection handling

## License
This project is open source and available under the MIT License.
