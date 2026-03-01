# Self-Hosted Auth Server — Setup Guide

## What You Get
- **Auth server** (Python) — runs on your laptop 24/7
- **Admin CLI** — generate keys, manage users, view logs from terminal
- **Loader integration** — replaces KeyAuth entirely (no 3rd party dependency)

## Architecture
```
[User's PC]                    [Your Laptop]
 Loader.exe  ──── HTTP ────►  server.py (port 7777)
   │                              │
   └─ self_auth.h                 └─ auth.db (SQLite)
      (WinHTTP)                      (keys, sessions, logs)
```

---

## Step 1: Set Up the Server (Your Laptop)

### Install Python
1. Download Python 3.10+ from https://python.org
2. During install, **check "Add Python to PATH"**
3. Verify: open terminal, run `python --version`

### Install Dependencies
```bash
cd auth-server
pip install -r requirements.txt
```

### Set Your Admin Key
Pick a strong secret key. Set it as an environment variable:

**Windows (PowerShell):**
```powershell
$env:AUTH_ADMIN_KEY = "your-secret-admin-key-here"
```

**To make it permanent (survives reboots):**
```powershell
[System.Environment]::SetEnvironmentVariable("AUTH_ADMIN_KEY", "your-secret-admin-key-here", "User")
```

### Start the Server
```bash
cd auth-server
python server.py
```

You should see:
```
  [+] Admin key loaded from environment.

  Auth server starting on 0.0.0.0:7777
  Database: C:\...\auth-server\auth.db
```

### (Optional) Run with Waitress (Production)
Flask's built-in server is fine for small scale. For better stability:
```bash
python -c "from waitress import serve; from server import app, init_db; init_db(); serve(app, host='0.0.0.0', port=7777)"
```

---

## Step 2: Open Your Port (So Users Can Connect)

### Option A: Port Forwarding (Simple)
1. Go to your router admin page (usually `192.168.1.1`)
2. Forward **port 7777** (TCP) to your laptop's local IP
3. Find your public IP at https://whatismyip.com
4. Users connect to `your-public-ip:7777`

### Option B: Cloudflare Tunnel (Recommended, Free)
No port forwarding needed. Hides your real IP.

1. Sign up at https://dash.cloudflare.com
2. Install `cloudflared`: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
3. Run:
```bash
cloudflared tunnel --url http://localhost:7777
```
4. It gives you a URL like `https://random-name.trycloudflare.com`
5. For a permanent subdomain, set up a named tunnel with your own domain

### Option C: Tailscale (Private, Zero Config)
If you only want YOUR machines to access it:
1. Install Tailscale on both machines
2. Use the Tailscale IP instead of public IP
3. No port forwarding needed

---

## Step 3: Generate License Keys

Set your admin key in the terminal first:
```powershell
$env:AUTH_ADMIN_KEY = "your-secret-admin-key-here"
```

Then use the admin CLI:

```bash
# Generate 1 key, valid 30 days
python admin.py genkeys

# Generate 5 keys, valid 7 days, with a note
python admin.py genkeys --days 7 --count 5 --note "testers"

# Generate a lifetime key (3650 days = 10 years)
python admin.py genkeys --days 3650 --note "lifetime"

# List all keys
python admin.py listkeys

# View active sessions
python admin.py sessions

# Revoke a key (get ID from listkeys)
python admin.py revoke --id 3

# Reset HWID (if user changes PC)
python admin.py resethwid --id 3

# Extend a key by 14 days
python admin.py extend --id 3 --days 14

# View auth logs
python admin.py logs
```

---

## Step 4: Configure the Loader

In `Loader/main.cpp`, find the auth config block and set your server address:

```cpp
// ═══════════════════════════════════════════════════════════════════
//  AUTH SERVER CONFIGURATION
// ═══════════════════════════════════════════════════════════════════
static std::string AUTH_SERVER_HOST = E("YOUR.PUBLIC.IP.HERE");
static int         AUTH_SERVER_PORT = 7777;
// ═══════════════════════════════════════════════════════════════════
```

**If using Cloudflare Tunnel**, the host is your tunnel domain (without https://),
and the port should be 443. You'll also need to change the WinHTTP request in
`self_auth.h` to use HTTPS (add `WINHTTP_FLAG_SECURE` flag).

**For local testing**, keep it as `127.0.0.1` / port `7777`.

---

## Step 5: Keep Server Running 24/7

### Windows Task Scheduler (Auto-start on boot)
1. Open Task Scheduler
2. Create Basic Task → Name: "Auth Server"
3. Trigger: "When the computer starts"
4. Action: Start a program
   - Program: `python`
   - Arguments: `C:\path\to\auth-server\server.py`
   - Start in: `C:\path\to\auth-server\`
5. Check "Run whether user is logged on or not"

### Or use NSSM (Non-Sucking Service Manager)
```bash
nssm install AuthServer python C:\path\to\auth-server\server.py
nssm set AuthServer AppDirectory C:\path\to\auth-server
nssm set AuthServer AppEnvironmentExtra AUTH_ADMIN_KEY=your-key-here
nssm start AuthServer
```

---

## How It Works

1. **User starts Loader** → connects to your server (`/api/status`)
2. **User enters license key** → Loader sends key + HWID hash to `/api/auth`
3. **First login**: server binds key to that machine's HWID
4. **Subsequent logins**: server verifies HWID matches (prevents key sharing)
5. **Heartbeat**: Loader pings `/api/heartbeat` every 60s to keep session alive
6. **Sessions expire** after 5 minutes without heartbeat (user closed loader)

### Security Features
- **HWID binding** — keys locked to one machine (admin can reset)
- **Rate limiting** — 10 failed attempts = 10 minute ban
- **Session limits** — configurable max concurrent sessions per key
- **Expiry dates** — keys auto-expire
- **Auth logging** — every login attempt logged with IP, HWID, timestamp

---

## API Reference (for custom tools)

All admin endpoints require `X-Admin-Key` header.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Server health check |
| POST | `/api/auth` | Login (`{"key":"...","hwid":"..."}`) |
| POST | `/api/heartbeat` | Keep alive (`{"session":"..."}`) |
| GET | `/api/admin/keys` | List all keys |
| POST | `/api/admin/keys` | Create keys |
| DELETE | `/api/admin/keys/<id>` | Revoke key |
| POST | `/api/admin/keys/<id>/reset-hwid` | Reset HWID |
| POST | `/api/admin/keys/<id>/extend` | Extend expiry |
| GET | `/api/admin/sessions` | List active sessions |
| POST | `/api/admin/sessions/kill` | Kill sessions |
| GET | `/api/admin/logs?limit=50` | View auth logs |
