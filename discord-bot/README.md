# Discord Injection Tracker Bot

Tracks license key injections and displays them in a Discord channel with rich embeds.

## Features
- **Injection logging** — Logs every injection with timestamp, Discord user, key, HWID
- **Active sessions** — Tracks who is currently online and for how long
- **Session duration** — Shows total time logged in when a user disconnects
- **Key management** — Add/remove/list license keys via Discord commands
- **HWID binding** — Automatically locks a key to the first machine that uses it
- **Failed attempts** — Logs denied injections (expired, HWID mismatch, invalid key)

## Setup

### 1. Create a Discord Bot
1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application → Bot → Copy the **Bot Token**
3. Enable **Message Content Intent** under Bot settings
4. Invite the bot to your server with `applications.commands` and `bot` scopes
   - Bot permissions: Send Messages, Embed Links, Read Message History

### 2. Configure
Edit `config.json`:
```json
{
    "bot_token": "YOUR_BOT_TOKEN_HERE",
    "log_channel_id": "YOUR_CHANNEL_ID_HERE",
    "webhook_secret": "PICK_A_RANDOM_SECRET",
    "webhook_port": 5000,
    "embed_color": 3066993
}
```
- **bot_token** — From step 1
- **log_channel_id** — Right-click the channel → Copy Channel ID
- **webhook_secret** — Any random string (must match the client-side secret)

### 3. Install & Run
```bash
cd discord-bot
pip install -r requirements.txt
python bot.py
```

## Discord Commands

| Command | Permission | Description |
|---------|-----------|-------------|
| `!sessions` | Everyone | Show currently active sessions |
| `!history [count]` | Everyone | Show recent injection history |
| `!addkey <KEY> <@user> [days]` | Admin | Add a license key |
| `!removekey <KEY>` | Admin | Remove a license key |
| `!keys` | Admin | List all license keys |
| `!logout <KEY\|all>` | Admin | Force logout a session |

## API Endpoints

The bot runs a webhook server on the configured port (default 5000).

### POST `/api/inject`
Called by the cheat client on successful injection.
```json
{
    "secret": "your_webhook_secret",
    "key": "XXXX-XXXX-XXXX-XXXX",
    "hwid": "machine_hardware_id",
    "version": "1.0.0"
}
```

### POST `/api/heartbeat`
Periodic keepalive from the client.
```json
{
    "secret": "your_webhook_secret",
    "key": "XXXX-XXXX-XXXX-XXXX"
}
```

### POST `/api/logout`
Called when the client shuts down cleanly.
```json
{
    "secret": "your_webhook_secret",
    "key": "XXXX-XXXX-XXXX-XXXX"
}
```

## Client Integration

The cheat client sends HTTP POST requests to these endpoints. The webhook secret must match `config.json`. See `auth_webhook.h` in the User project for the C++ integration.
