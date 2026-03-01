Self-Hosted Auth Server — Ready to Deploy

Files to copy to your 2nd PC (C:\auth-server\):
- server.py          (main server)
- admin.py           (CLI tool for key management)
- requirements.txt   (Python dependencies)

Quick Setup:
1. Install Python 3.10+ from python.org (check "Add to PATH")
2. Copy these 3 files to C:\auth-server\
3. Open Command Prompt as Admin and run:
   pip install -r requirements.txt
   set AUTH_ADMIN_KEY=PickAStrongSecret123
   python server.py

The server will start on port 7777 and show security status.

Generate keys:
set AUTH_ADMIN_KEY=PickAStrongSecret123
python admin.py genkeys --days 30

Loader connects to: 73.137.88.21:7777

Security Features:
- HMAC-SHA256 request signing
- Admin endpoints localhost only
- 30s anti-replay window
- 5-failure rate limit (10 min ban)
- 4KB request size limit
- Generic error responses
