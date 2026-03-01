# Fresh Windows PC Setup Guide — Auth Server

This guide walks you through setting up the auth server on a **brand new Windows PC** with nothing installed.

---

## Step 1: Install Python

1. Open Microsoft Edge (or any browser)
2. Go to: https://www.python.org/downloads/
3. Click **Download Python 3.12.x** (or latest stable)
4. Run the installer
5. **CRITICAL**: On the first screen, check **"Add Python to PATH"**
6. Click "Install Now"
7. Wait for installation, then click "Close"

### Verify Python
1. Press `Win + R`, type `cmd`, press Enter
2. Type: `python --version`
3. You should see: `Python 3.12.x`

---

## Step 2: Install Git

1. Open browser, go to: https://git-scm.com/download/win
2. Download "Git for Windows Setup"
3. Run the installer
4. Accept all defaults (click Next through all screens)
5. When done, click "Finish"

### Verify Git
1. Open Command Prompt (if closed, press `Win + R`, type `cmd`, Enter)
2. Type: `git --version`
3. You should see: `git version 2.x.x`

---

## Step 3: Get the Auth Server Files

You have two options:

### Option A: Copy from USB/Network (Easiest)
1. Copy the entire `auth-server` folder from your main PC to the new PC
2. Place it somewhere easy to remember, like `C:\auth-server`

### Option B: Clone from GitHub (if you pushed it)
1. Open Command Prompt
2. Navigate to where you want the files:
   ```cmd
   cd C:\
   ```
3. Clone the repository:
   ```cmd
   git clone https://github.com/yourusername/yourrepo.git auth-server
   ```
4. If you don't have it on GitHub, use Option A

---

## Step 4: Install Python Dependencies

1. Open Command Prompt
2. Navigate to the auth-server folder:
   ```cmd
   cd C:\auth-server
   ```
3. Install the required packages:
   ```cmd
   pip install -r requirements.txt
   ```
4. Wait for it to complete (should take < 30 seconds)

---

## Step 5: Set Your Admin Key

Pick a strong secret key. This protects your admin endpoints.

### Set It For Current Session
1. In the same Command Prompt, type:
   ```cmd
   set AUTH_ADMIN_KEY=MySuperSecretKey123!@#
   ```
2. **Replace `MySuperSecretKey123!@#` with your own secret**

### Make It Permanent (Survives Reboots)
1. Open PowerShell (press `Win + R`, type `powershell`, Enter)
2. Type:
   ```powershell
   [System.Environment]::SetEnvironmentVariable("AUTH_ADMIN_KEY", "MySuperSecretKey123!@#", "User")
   ```
3. Replace the key with your own
4. Close PowerShell

---

## Step 6: Test the Server

1. In Command Prompt (still in `C:\auth-server`):
   ```cmd
   python server.py
   ```
2. You should see:
   ```
     [+] Admin key loaded from environment.

     Auth server starting on 0.0.0.0:7777
     Database: C:\auth-server\auth.db
   ```
3. **Leave this window open** — the server is now running!

### Test Connection
1. Open a NEW Command Prompt (don't close the server)
2. Type:
   ```cmd
   curl http://localhost:7777/api/status
   ```
3. You should see JSON response like:
   ```json
   {"success":true,"message":"Auth server online.","time":1738032000}
   ```

If you see this, the server is working!

---

## Step 7: Generate Your First License Key

1. Open a NEW Command Prompt
2. Navigate to the auth-server folder:
   ```cmd
   cd C:\auth-server
   ```
3. Set the admin key (if not permanent):
   ```cmd
   set AUTH_ADMIN_KEY=MySuperSecretKey123!@#
   ```
4. Generate a key:
   ```cmd
   python admin.py genkeys --days 30 --count 1 --note "first test key"
   ```
5. You should see output like:
   ```
     Generated 1 key(s), expires in 30 days:

     EXT-AB12CD34-EF56GH78
   ```
6. **Copy this key** — you'll need it for the loader

---

## Step 8: Configure Your Router (Port Forwarding)

This lets users from the internet connect to your server.

### Find Your PC's IP Address
1. In Command Prompt, type:
   ```cmd
   ipconfig
   ```
2. Look for "IPv4 Address" under your main connection (usually Wi-Fi or Ethernet)
3. Note it down (e.g., `192.168.1.105`)

### Port Forward (Router Setup)
1. Open browser, go to your router's admin page
   - Usually `192.168.1.1` or `192.168.0.1`
   - Login with router username/password
2. Find "Port Forwarding" or "Virtual Server"
3. Add a new rule:
   - **Service/Application**: Auth Server
   - **External Port**: 7777
   - **Internal Port**: 7777
   - **Protocol**: TCP
   - **Internal IP**: Your PC's IP from above (e.g., `192.168.1.105`)
   - **Enabled**: Yes
4. Save/Apply the changes

### Find Your Public IP
1. Go to: https://whatismyip.com
2. Note your public IP (e.g., `123.45.67.89`)

---

## Step 9: Update the Loader

On your main development PC:

1. Open `Loader/main.cpp`
2. Find this section (around line 400):
   ```cpp
   static std::string AUTH_SERVER_HOST = E("127.0.0.1");
   static int         AUTH_SERVER_PORT = 7777;
   ```
3. Change `127.0.0.1` to your public IP:
   ```cpp
   static std::string AUTH_SERVER_HOST = E("123.45.67.89");  // Your public IP
   static int         AUTH_SERVER_PORT = 7777;
   ```
4. Rebuild the loader

---

## Step 10: Test Everything

1. Make sure the server is still running on the 2nd PC
2. Run the loader on your main PC
3. Enter the license key you generated in Step 7
4. You should see "Authentication verified!"

If it works, congrats! Your auth server is live.

---

## Step 11: Make Server Run 24/7 (Auto-start on Boot)

### Using Windows Task Scheduler (Easiest)

1. Press `Win + S`, type "Task Scheduler", open it
2. Click "Create Basic Task" in the right panel
3. **Name**: `Auth Server`
4. **Description**: `Starts the auth server on boot`
5. **Trigger**: "When the computer starts" → Next
6. **Action**: "Start a program" → Next
7. **Program/script**: `python`
8. **Add arguments**: `C:\auth-server\server.py`
9. **Start in**: `C:\auth-server`
10. Check "Open the Properties dialog for this task when I click Finish"
11. Click Finish
12. In Properties:
    - **General tab**: Check "Run whether user is logged on or not"
    - **Settings tab**: Uncheck "Stop if the computer switches to battery power"
13. Click OK

### Test Auto-start
1. Reboot the 2nd PC
2. After boot, wait 30 seconds
3. Open Command Prompt and test:
   ```cmd
   curl http://localhost:7777/api/status
   ```
4. If you get a response, auto-start is working!

---

## Step 12: Secure Your Server

### Windows Firewall
1. Press `Win + S`, type "Windows Defender Firewall", open it
2. Click "Advanced settings" on the left
3. Click "Inbound Rules" → "New Rule..."
4. **Rule Type**: Port → Next
5. **TCP**, **Specific local ports**: `7777` → Next
6. **Allow the connection** → Next
7. Check all profiles (Domain, Private, Public) → Next
8. **Name**: `Auth Server Port 7777` → Finish

### Keep Windows Updated
1. Press `Win + I` to open Settings
2. Go to "Update & Security" → "Windows Update"
3. Click "Check for updates"
4. Install any available updates

### Optional: Use Cloudflare Tunnel (Hide Your IP)
If you don't want your public IP exposed:

1. Sign up at https://dash.cloudflare.com
2. Download `cloudflared`: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
3. Install it (next, next, finish)
4. Open Command Prompt as Administrator
5. Run:
   ```cmd
   cloudflared tunnel --url http://localhost:7777
   ```
6. It gives you a URL like `https://random-name.trycloudflare.com`
7. Update your loader to use that URL (change port to 443 in `self_auth.h` for HTTPS)

---

## Quick Reference Commands

### Server Management
```cmd
# Start server
cd C:\auth-server
python server.py

# Generate keys
python admin.py genkeys --days 30 --count 5

# List keys
python admin.py listkeys

# View active sessions
python admin.py sessions

# View logs
python admin.py logs

# Revoke a key
python admin.py revoke --id 3

# Reset HWID (user changed PC)
python admin.py resethwid --id 3
```

### Troubleshooting
```cmd
# Check if server is running
curl http://localhost:7777/api/status

# Check your IP
ipconfig

# Check Python version
python --version

# Check installed packages
pip list
```

---

## You're Done!

Your auth server is now:
- ✅ Running 24/7 on the 2nd PC
- ✅ Accessible from the internet
- ✅ Generating and managing license keys
- ✅ Integrated with your loader

Keep the server window open or use Task Scheduler for auto-start. The server will create `auth.db` automatically to store keys and sessions.

---

## Need Help?

If something doesn't work:
1. Check the server window for error messages
2. Verify your port forwarding settings
3. Make sure Windows Firewall allows port 7777
4. Test locally first (`curl http://localhost:7777/api/status`)
5. Then test from another device on your network
6. Finally test from the internet using your public IP

The server is very lightweight — it can handle hundreds of users easily on a basic PC.
