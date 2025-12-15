import discord
import os
from dotenv import load_dotenv
from mcrcon import MCRcon

# Load environment variables
load_dotenv()

DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
RCON_HOST = os.getenv('RCON_HOST')
RCON_PORT = int(os.getenv('RCON_PORT', 25575))
RCON_PASSWORD = os.getenv('RCON_PASSWORD')
REQUEST_CHANNEL_ID = int(os.getenv('REQUEST_CHANNEL_ID'))
ADMIN_CHANNEL_ID = int(os.getenv('ADMIN_CHANNEL_ID'))

# Setup Discord intents
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

client = discord.Client(intents=intents)


class WhitelistRequestView(discord.ui.View):
    def __init__(self, username):
        super().__init__(timeout=None)
        self.username = username

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.green)
    async def approve_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            # Connect to RCON and whitelist the user
            with MCRcon(RCON_HOST, RCON_PASSWORD, RCON_PORT) as mcr:
                response = mcr.command(f"whitelist add {self.username}")
                print(f"RCON Response: {response}")
            
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
            print(f"RCON Error: {e}")

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
    print(f'{client.user} has connected to Discord!')


@client.event
async def on_message(message):
    # Ignore messages from the bot itself
    if message.author == client.user:
        return
    
    # Check if message is in the request channel
    if message.channel.id == REQUEST_CHANNEL_ID:
        # Extract username from message (assuming the message contains just the username)
        username = message.content.strip()
        
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
            print(f"Error: Could not find admin channel with ID {ADMIN_CHANNEL_ID}")


# Run the bot
if __name__ == "__main__":
    client.run(DISCORD_TOKEN)
