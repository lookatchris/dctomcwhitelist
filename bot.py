import discord
import os
import re
import logging
from dotenv import load_dotenv
from mcrcon import MCRcon

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

try:
    REQUEST_CHANNEL_ID = int(os.getenv('REQUEST_CHANNEL_ID'))
except (TypeError, ValueError):
    raise ValueError("REQUEST_CHANNEL_ID must be a valid integer")

try:
    ADMIN_CHANNEL_ID = int(os.getenv('ADMIN_CHANNEL_ID'))
except (TypeError, ValueError):
    raise ValueError("ADMIN_CHANNEL_ID must be a valid integer")

# Setup Discord intents
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

client = discord.Client(intents=intents)


def is_valid_minecraft_username(username):
    """
    Validates a Minecraft username.
    Minecraft usernames must be 3-16 characters, containing only letters, numbers, and underscores.
    """
    return bool(re.match(r'^[a-zA-Z0-9_]{3,16}$', username))


class WhitelistRequestView(discord.ui.View):
    def __init__(self, username):
        super().__init__(timeout=None)
        self.username = username

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.green)
    async def approve_button(self, interaction: discord.Interaction, button: discord.ui.Button):
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
            
            # Update the message to show approval
            embed = interaction.message.embeds[0]
            embed.color = discord.Color.green()
            embed.title = "Whitelist Request - Approved"
            embed.add_field(name="Status", value="✅ Approved", inline=False)
            embed.add_field(name="Approved by", value=interaction.user.mention, inline=False)
            
            await interaction.response.edit_message(embed=embed, view=None)
            
        except Exception as e:
            await interaction.response.send_message(
                f"Error connecting to RCON or executing command: {str(e)}", 
                ephemeral=True
            )
            logger.error(f"RCON Error: {e}")

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.red)
    async def deny_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Update the message to show denial
        embed = interaction.message.embeds[0]
        embed.color = discord.Color.red()
        embed.title = "Whitelist Request - Denied"
        embed.add_field(name="Status", value="❌ Denied", inline=False)
        embed.add_field(name="Denied by", value=interaction.user.mention, inline=False)
        
        await interaction.response.edit_message(embed=embed, view=None)


@client.event
async def on_ready():
    logger.info(f'{client.user} has connected to Discord!')


@client.event
async def on_message(message):
    # Ignore messages from the bot itself
    if message.author == client.user:
        return
    
    # Check if message is in the request channel
    if message.channel.id == REQUEST_CHANNEL_ID:
        # Extract username from message (assuming the message contains just the username)
        username = message.content.strip()
        
        # Validate username format
        if not is_valid_minecraft_username(username):
            await message.channel.send(
                f"Invalid username format. Minecraft usernames must be 3-16 characters, "
                f"containing only letters, numbers, and underscores."
            )
            return
        
        # Create the view with approve/deny buttons
        view = WhitelistRequestView(username)
        
        # Create embed for admin channel
        embed = discord.Embed(
            title="Whitelist Request",
            description=f"New whitelist request received",
            color=discord.Color.blue()
        )
        embed.add_field(name="Username", value=username, inline=False)
        embed.add_field(name="Requested by", value=message.author.mention, inline=False)
        embed.add_field(name="Channel", value=message.channel.mention, inline=False)
        
        # Send to admin channel
        admin_channel = client.get_channel(ADMIN_CHANNEL_ID)
        if admin_channel:
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
    client.run(DISCORD_TOKEN)
