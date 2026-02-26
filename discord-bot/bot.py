"""
Discord Injection Tracker Bot
Tracks license key injections and displays them in a Discord channel.

Features:
  - Flask webhook server receives injection events from the cheat client
  - Logs each injection with timestamp, Discord user, key, and HWID
  - Tracks active sessions with login/duration
  - Discord commands: !sessions, !history, !addkey, !removekey, !keys
"""

import json
import os
import asyncio
import threading
from datetime import datetime, timezone, timedelta

import discord
from discord.ext import commands, tasks
from flask import Flask, request, jsonify

# ── Load Config ──────────────────────────────────────────────────────

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
KEYS_PATH = os.path.join(os.path.dirname(__file__), "keys.json")

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

BOT_TOKEN = config["bot_token"]
LOG_CHANNEL_ID = int(config["log_channel_id"])
WEBHOOK_SECRET = config["webhook_secret"]
WEBHOOK_PORT = config.get("webhook_port", 5000)
EMBED_COLOR = config.get("embed_color", 0x2ECC71)

# ── Key Database ─────────────────────────────────────────────────────

def load_keys():
    if not os.path.exists(KEYS_PATH):
        return {"keys": {}}
    with open(KEYS_PATH, "r") as f:
        return json.load(f)

def save_keys(data):
    with open(KEYS_PATH, "w") as f:
        json.dump(data, f, indent=4, default=str)

# ── Active Sessions ──────────────────────────────────────────────────

active_sessions = {}
# Format: { "key": { "discord_name": str, "discord_id": str,
#                     "login_time": datetime, "hwid": str } }

injection_history = []
# Format: [ { "key": str, "discord_name": str, "discord_id": str,
#             "hwid": str, "time": str, "ip": str } ]

# ── Discord Bot ──────────────────────────────────────────────────────

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    print(f"[Bot] Logged in as {bot.user} (ID: {bot.user.id})")
    print(f"[Bot] Logging to channel: {LOG_CHANNEL_ID}")
    update_presence.start()


@tasks.loop(minutes=5)
async def update_presence():
    count = len(active_sessions)
    activity = discord.Activity(
        type=discord.ActivityType.watching,
        name=f"{count} active session{'s' if count != 1 else ''}"
    )
    await bot.change_presence(activity=activity)


@bot.command(name="sessions")
async def cmd_sessions(ctx):
    """Show all currently active sessions."""
    if not active_sessions:
        embed = discord.Embed(
            title="Active Sessions",
            description="No active sessions.",
            color=0x95A5A6,
            timestamp=datetime.now(timezone.utc)
        )
        await ctx.send(embed=embed)
        return

    embed = discord.Embed(
        title=f"Active Sessions ({len(active_sessions)})",
        color=EMBED_COLOR,
        timestamp=datetime.now(timezone.utc)
    )

    for key, session in active_sessions.items():
        login_time = session["login_time"]
        duration = datetime.now(timezone.utc) - login_time
        hours, remainder = divmod(int(duration.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        masked_key = key[:4] + "-****-****-" + key[-4:]
        embed.add_field(
            name=f"{session['discord_name']}",
            value=(
                f"**Key:** `{masked_key}`\n"
                f"**Logged in:** <t:{int(login_time.timestamp())}:R>\n"
                f"**Duration:** `{hours}h {minutes}m {seconds}s`\n"
                f"**HWID:** `{session.get('hwid', 'N/A')[:12]}...`"
            ),
            inline=True
        )

    await ctx.send(embed=embed)


@bot.command(name="history")
async def cmd_history(ctx, count: int = 10):
    """Show recent injection history. Usage: !history [count]"""
    count = min(count, 25)
    recent = injection_history[-count:] if injection_history else []

    if not recent:
        embed = discord.Embed(
            title="Injection History",
            description="No injections recorded yet.",
            color=0x95A5A6,
            timestamp=datetime.now(timezone.utc)
        )
        await ctx.send(embed=embed)
        return

    embed = discord.Embed(
        title=f"Recent Injections (last {len(recent)})",
        color=EMBED_COLOR,
        timestamp=datetime.now(timezone.utc)
    )

    for entry in reversed(recent):
        masked_key = entry["key"][:4] + "-****-****-" + entry["key"][-4:]
        embed.add_field(
            name=f"{entry['discord_name']}",
            value=(
                f"**Key:** `{masked_key}`\n"
                f"**Time:** `{entry['time']}`\n"
                f"**HWID:** `{entry.get('hwid', 'N/A')[:12]}...`"
            ),
            inline=True
        )

    await ctx.send(embed=embed)


@bot.command(name="addkey")
@commands.has_permissions(administrator=True)
async def cmd_addkey(ctx, key: str, discord_user: discord.Member, days: int = 30):
    """Add a license key. Usage: !addkey <KEY> <@user> [days]"""
    db = load_keys()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=days)

    db["keys"][key] = {
        "discord_id": str(discord_user.id),
        "discord_name": discord_user.display_name,
        "hwid": "",
        "created_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "max_uses": 1
    }
    save_keys(db)

    embed = discord.Embed(
        title="Key Added",
        color=0x2ECC71,
        timestamp=now
    )
    embed.add_field(name="Key", value=f"`{key}`", inline=False)
    embed.add_field(name="User", value=discord_user.mention, inline=True)
    embed.add_field(name="Expires", value=f"<t:{int(expires.timestamp())}:F>", inline=True)
    await ctx.send(embed=embed)


@bot.command(name="removekey")
@commands.has_permissions(administrator=True)
async def cmd_removekey(ctx, key: str):
    """Remove a license key. Usage: !removekey <KEY>"""
    db = load_keys()
    if key in db["keys"]:
        del db["keys"][key]
        save_keys(db)
        await ctx.send(f"Key `{key}` removed.")
    else:
        await ctx.send(f"Key `{key}` not found.")


@bot.command(name="keys")
@commands.has_permissions(administrator=True)
async def cmd_keys(ctx):
    """List all license keys (admin only)."""
    db = load_keys()
    keys = db.get("keys", {})

    if not keys:
        await ctx.send("No keys registered.")
        return

    embed = discord.Embed(
        title=f"License Keys ({len(keys)})",
        color=EMBED_COLOR,
        timestamp=datetime.now(timezone.utc)
    )

    for key, info in keys.items():
        masked_key = key[:4] + "-****-****-" + key[-4:]
        expires = info.get("expires_at", "N/A")
        embed.add_field(
            name=masked_key,
            value=(
                f"**User:** {info.get('discord_name', 'Unknown')}\n"
                f"**Expires:** `{expires[:10]}`\n"
                f"**HWID:** `{info.get('hwid', 'Not bound')[:12] or 'Not bound'}`"
            ),
            inline=True
        )

    await ctx.send(embed=embed)


@bot.command(name="logout")
@commands.has_permissions(administrator=True)
async def cmd_logout(ctx, key: str = None):
    """Force logout a session. Usage: !logout <KEY> or !logout all"""
    if key == "all":
        count = len(active_sessions)
        active_sessions.clear()
        await ctx.send(f"Cleared {count} active session(s).")
    elif key and key in active_sessions:
        session = active_sessions.pop(key)
        await ctx.send(f"Logged out `{session['discord_name']}`.")
    elif key:
        await ctx.send(f"No active session found for key `{key[:4]}...`.")
    else:
        await ctx.send("Usage: `!logout <KEY>` or `!logout all`")


# ── Flask Webhook Server ─────────────────────────────────────────────

app = Flask(__name__)


def validate_key(key, hwid):
    """Validate a license key and return (valid, info_or_error)."""
    db = load_keys()
    keys = db.get("keys", {})

    if key not in keys:
        return False, "Invalid key"

    info = keys[key]

    # Check expiry
    expires = datetime.fromisoformat(info["expires_at"])
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires:
        return False, "Key expired"

    # Check HWID binding
    if info["hwid"] and info["hwid"] != hwid:
        return False, "HWID mismatch"

    # Bind HWID on first use
    if not info["hwid"]:
        info["hwid"] = hwid
        save_keys(db)

    return True, info


@app.route("/api/inject", methods=["POST"])
def handle_inject():
    """
    Endpoint called by the cheat client on successful injection.
    
    Expected JSON body:
    {
        "secret": "webhook_secret",
        "key": "XXXX-XXXX-XXXX-XXXX",
        "hwid": "machine_hardware_id",
        "version": "1.0.0"  (optional)
    }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    # Validate secret
    if data.get("secret") != WEBHOOK_SECRET:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    key = data.get("key", "")
    hwid = data.get("hwid", "unknown")
    version = data.get("version", "unknown")

    if not key:
        return jsonify({"status": "error", "message": "No key provided"}), 400

    # Validate key
    valid, result = validate_key(key, hwid)
    if not valid:
        # Log failed attempt
        asyncio.run_coroutine_threadsafe(
            log_failed_injection(key, hwid, result, request.remote_addr),
            bot.loop
        )
        return jsonify({"status": "error", "message": result}), 403

    info = result
    now = datetime.now(timezone.utc)

    # Register active session
    active_sessions[key] = {
        "discord_name": info["discord_name"],
        "discord_id": info["discord_id"],
        "login_time": now,
        "hwid": hwid,
        "version": version
    }

    # Add to history
    entry = {
        "key": key,
        "discord_name": info["discord_name"],
        "discord_id": info["discord_id"],
        "hwid": hwid,
        "time": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "ip": request.remote_addr,
        "version": version
    }
    injection_history.append(entry)

    # Send Discord embed
    asyncio.run_coroutine_threadsafe(
        log_injection(entry, info),
        bot.loop
    )

    return jsonify({
        "status": "ok",
        "message": "Injection logged",
        "discord_name": info["discord_name"]
    }), 200


@app.route("/api/heartbeat", methods=["POST"])
def handle_heartbeat():
    """
    Periodic heartbeat from the client to keep session alive.
    
    Expected JSON body:
    {
        "secret": "webhook_secret",
        "key": "XXXX-XXXX-XXXX-XXXX"
    }
    """
    data = request.get_json(silent=True)
    if not data or data.get("secret") != WEBHOOK_SECRET:
        return jsonify({"status": "error"}), 401

    key = data.get("key", "")
    if key in active_sessions:
        return jsonify({"status": "ok"}), 200

    return jsonify({"status": "expired"}), 410


@app.route("/api/logout", methods=["POST"])
def handle_logout():
    """
    Called when the client shuts down cleanly.
    
    Expected JSON body:
    {
        "secret": "webhook_secret",
        "key": "XXXX-XXXX-XXXX-XXXX"
    }
    """
    data = request.get_json(silent=True)
    if not data or data.get("secret") != WEBHOOK_SECRET:
        return jsonify({"status": "error"}), 401

    key = data.get("key", "")
    if key in active_sessions:
        session = active_sessions.pop(key)
        duration = datetime.now(timezone.utc) - session["login_time"]
        asyncio.run_coroutine_threadsafe(
            log_logout(session, duration),
            bot.loop
        )
        return jsonify({"status": "ok"}), 200

    return jsonify({"status": "not_found"}), 404


# ── Discord Logging Functions ────────────────────────────────────────

async def log_injection(entry, key_info):
    """Send an injection log embed to the Discord channel."""
    channel = bot.get_channel(LOG_CHANNEL_ID)
    if not channel:
        print(f"[Bot] ERROR: Channel {LOG_CHANNEL_ID} not found")
        return

    masked_key = entry["key"][:4] + "-****-****-" + entry["key"][-4:]
    expires = key_info.get("expires_at", "N/A")[:10]

    embed = discord.Embed(
        title="Injection Logged",
        color=0x2ECC71,
        timestamp=datetime.now(timezone.utc)
    )
    embed.set_thumbnail(url="https://cdn-icons-png.flaticon.com/512/6941/6941697.png")

    embed.add_field(name="User", value=f"<@{entry['discord_id']}>", inline=True)
    embed.add_field(name="Key", value=f"`{masked_key}`", inline=True)
    embed.add_field(name="Version", value=f"`{entry.get('version', 'N/A')}`", inline=True)
    embed.add_field(name="Time", value=f"`{entry['time']}`", inline=True)
    embed.add_field(name="Expires", value=f"`{expires}`", inline=True)
    embed.add_field(name="HWID", value=f"`{entry['hwid'][:16]}...`", inline=True)

    embed.set_footer(text=f"IP: {entry.get('ip', 'N/A')}")

    await channel.send(embed=embed)


async def log_failed_injection(key, hwid, reason, ip):
    """Send a failed injection log embed."""
    channel = bot.get_channel(LOG_CHANNEL_ID)
    if not channel:
        return

    masked_key = key[:4] + "-****" if len(key) >= 4 else "????"

    embed = discord.Embed(
        title="Injection Denied",
        color=0xE74C3C,
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="Key", value=f"`{masked_key}`", inline=True)
    embed.add_field(name="Reason", value=f"`{reason}`", inline=True)
    embed.add_field(name="HWID", value=f"`{hwid[:16]}...`" if hwid else "`N/A`", inline=True)
    embed.set_footer(text=f"IP: {ip}")

    await channel.send(embed=embed)


async def log_logout(session, duration):
    """Send a logout log embed."""
    channel = bot.get_channel(LOG_CHANNEL_ID)
    if not channel:
        return

    hours, remainder = divmod(int(duration.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)

    embed = discord.Embed(
        title="Session Ended",
        color=0xF39C12,
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(
        name="User",
        value=f"<@{session['discord_id']}>",
        inline=True
    )
    embed.add_field(
        name="Duration",
        value=f"`{hours}h {minutes}m {seconds}s`",
        inline=True
    )

    await channel.send(embed=embed)


# ── Start Both Services ──────────────────────────────────────────────

def run_flask():
    """Run Flask in a separate thread."""
    app.run(host="0.0.0.0", port=WEBHOOK_PORT, use_reloader=False)


if __name__ == "__main__":
    print("[Bot] Starting Discord Injection Tracker...")
    print(f"[Bot] Webhook server will listen on port {WEBHOOK_PORT}")

    # Start Flask webhook server in background thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    # Start Discord bot (blocks)
    bot.run(BOT_TOKEN)
