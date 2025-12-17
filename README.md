# dctomcwhitelist
Discord Bot which interacts with a Minecraft Server

## Overview
This Discord bot automates the Minecraft server whitelist process. Users can submit their Minecraft username in a designated Discord channel, and administrators can approve or deny requests via Discord buttons. Approved requests automatically whitelist the user on the Minecraft server via RCON.

## Features
- **Automated Whitelist Requests**: Users submit their Minecraft username in a request channel
- **Admin Approval System**: Admins receive formatted requests with Approve/Deny buttons
- **RCON Integration**: Approved requests automatically whitelist users on the Minecraft server
- **Input Validation**: Validates Minecraft username format to prevent command injection
- **Error Handling**: Comprehensive error handling for RCON connections and invalid inputs
- **Logging**: Detailed logging for debugging and monitoring

## Setup

### Prerequisites
- Python 3.8 or higher
- A Discord bot token ([Create a bot](https://discord.com/developers/applications))
- Minecraft server with RCON enabled

### Installation

1. Clone the repository:
```bash
git clone https://github.com/lookatchris/dctomcwhitelist.git
cd dctomcwhitelist
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
   - Copy `.env.example` to `.env`
   - Fill in your configuration:

```env
DISCORD_TOKEN=your_discord_bot_token_here
RCON_HOST=your_minecraft_server_ip
RCON_PORT=25575
RCON_PASSWORD=your_rcon_password
REQUEST_CHANNEL_ID=123456789012345678
ADMIN_CHANNEL_ID=123456789012345678
ADMIN_ROLE_IDS=111111111111111111,222222222222222222  # comma-separated admin roles; or use ADMIN_ROLE_ID for a single role
WARN_ROLE_ID_1=333333333333333333  # role applied at warning level 1
WARN_ROLE_ID_2=444444444444444444  # role applied at warning level 2
```

### Getting Discord Channel IDs
1. Enable Developer Mode in Discord (User Settings > Advanced > Developer Mode)
2. Right-click on a channel and select "Copy ID"

### Running the Bot
```bash
python bot.py
```

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
