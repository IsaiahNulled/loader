#!/usr/bin/env python3
"""
Admin CLI for managing the auth server.
Usage: python admin.py <command> [options]

Commands:
    genkeys     Generate license keys
    listkeys    List all keys
    revoke      Revoke a key by ID
    resethwid   Reset HWID binding for a key
    extend      Extend a key's expiry
    sessions    List active sessions
    killall     Kill all active sessions
    logs        View recent auth logs

Examples:
    python admin.py genkeys --days 30 --count 5 --note "batch1"
    python admin.py listkeys
    python admin.py revoke --id 3
    python admin.py resethwid --id 3
    python admin.py extend --id 3 --days 14
    python admin.py sessions
    python admin.py logs --limit 20
"""

import os
import sys
import json
import argparse
import urllib.request
import urllib.error

SERVER_URL = os.environ.get("AUTH_SERVER_URL", "http://127.0.0.1:7777")
ADMIN_KEY  = os.environ.get("AUTH_ADMIN_KEY", "")

def api(method, path, data=None):
    url = f"{SERVER_URL}{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("X-Admin-Key", ADMIN_KEY)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return json.loads(body)
        except:
            return {"success": False, "message": f"HTTP {e.code}: {body}"}
    except urllib.error.URLError as e:
        return {"success": False, "message": f"Connection failed: {e.reason}"}

def cmd_genkeys(args):
    resp = api("POST", "/api/admin/keys", {
        "days": args.days,
        "count": args.count,
        "note": args.note,
        "max_sessions": args.max_sessions,
        "prefix": args.prefix,
    })
    if resp.get("success"):
        print(f"\n  Generated {len(resp['keys'])} key(s), expires in {resp['expires_in_days']} days:\n")
        for k in resp["keys"]:
            print(f"    {k}")
        print()
    else:
        print(f"  Error: {resp.get('message')}")

def cmd_listkeys(args):
    resp = api("GET", "/api/admin/keys")
    if not resp.get("success"):
        print(f"  Error: {resp.get('message')}")
        return

    keys = resp["keys"]
    if not keys:
        print("\n  No keys found.\n")
        return

    print(f"\n  {'ID':>4}  {'Key':<30}  {'Status':<10}  {'HWID':<6}  {'Sessions':<9}  {'Expires':<20}  {'Note'}")
    print(f"  {'─'*4}  {'─'*30}  {'─'*10}  {'─'*6}  {'─'*9}  {'─'*20}  {'─'*15}")
    for k in keys:
        status = "Active" if k["enabled"] else "Revoked"
        hwid = "Bound" if k["hwid_bound"] else "Open"
        print(f"  {k['id']:>4}  {k['key']:<30}  {status:<10}  {hwid:<6}  {k['active_sessions']:<9}  {k['expires']:<20}  {k['note']}")
    print()

def cmd_revoke(args):
    resp = api("DELETE", f"/api/admin/keys/{args.id}")
    print(f"  {'Done' if resp.get('success') else 'Error'}: {resp.get('message')}")

def cmd_resethwid(args):
    resp = api("POST", f"/api/admin/keys/{args.id}/reset-hwid")
    print(f"  {'Done' if resp.get('success') else 'Error'}: {resp.get('message')}")

def cmd_extend(args):
    resp = api("POST", f"/api/admin/keys/{args.id}/extend", {"days": args.days})
    print(f"  {'Done' if resp.get('success') else 'Error'}: {resp.get('message')}")

def cmd_sessions(args):
    resp = api("GET", "/api/admin/sessions")
    if not resp.get("success"):
        print(f"  Error: {resp.get('message')}")
        return
    sessions = resp["sessions"]
    if not sessions:
        print("\n  No active sessions.\n")
        return
    print(f"\n  {'License':<30}  {'IP':<16}  {'Last Seen':<20}  {'Note'}")
    print(f"  {'─'*30}  {'─'*16}  {'─'*20}  {'─'*15}")
    for s in sessions:
        print(f"  {s['license']:<30}  {s['ip']:<16}  {s['last_seen']:<20}  {s['note']}")
    print()

def cmd_killall(args):
    resp = api("POST", "/api/admin/sessions/kill", {})
    print(f"  {'Done' if resp.get('success') else 'Error'}: {resp.get('message')}")

def cmd_logs(args):
    resp = api("GET", f"/api/admin/logs?limit={args.limit}")
    if not resp.get("success"):
        print(f"  Error: {resp.get('message')}")
        return
    logs = resp["logs"]
    if not logs:
        print("\n  No logs.\n")
        return
    print(f"\n  {'Time':<20}  {'Action':<8}  {'OK':<4}  {'Key':<30}  {'IP':<16}  {'Message'}")
    print(f"  {'─'*20}  {'─'*8}  {'─'*4}  {'─'*30}  {'─'*16}  {'─'*20}")
    for l in logs:
        ok = "Yes" if l["success"] else "No"
        print(f"  {l['time']:<20}  {l['action']:<8}  {ok:<4}  {(l['key'] or ''):<30}  {l['ip']:<16}  {l['message']}")
    print()

def main():
    if not ADMIN_KEY:
        print("  Error: AUTH_ADMIN_KEY environment variable not set.")
        print("  Set it to the same value as the server's admin key.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Auth Server Admin CLI")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("genkeys", help="Generate license keys")
    p.add_argument("--days", type=int, default=30, help="Days until expiry (default: 30)")
    p.add_argument("--count", type=int, default=1, help="Number of keys (default: 1)")
    p.add_argument("--note", type=str, default="", help="Note for the keys")
    p.add_argument("--max-sessions", type=int, default=1, help="Max concurrent sessions (default: 1)")
    p.add_argument("--prefix", type=str, default="EXT", help="Key prefix (default: EXT)")

    sub.add_parser("listkeys", help="List all keys")

    p = sub.add_parser("revoke", help="Revoke a key")
    p.add_argument("--id", type=int, required=True, help="Key ID to revoke")

    p = sub.add_parser("resethwid", help="Reset HWID for a key")
    p.add_argument("--id", type=int, required=True, help="Key ID to reset")

    p = sub.add_parser("extend", help="Extend key expiry")
    p.add_argument("--id", type=int, required=True, help="Key ID to extend")
    p.add_argument("--days", type=int, default=30, help="Days to add (default: 30)")

    sub.add_parser("sessions", help="List active sessions")
    sub.add_parser("killall", help="Kill all sessions")

    p = sub.add_parser("logs", help="View auth logs")
    p.add_argument("--limit", type=int, default=50, help="Number of entries (default: 50)")

    args = parser.parse_args()

    commands = {
        "genkeys": cmd_genkeys,
        "listkeys": cmd_listkeys,
        "revoke": cmd_revoke,
        "resethwid": cmd_resethwid,
        "extend": cmd_extend,
        "sessions": cmd_sessions,
        "killall": cmd_killall,
        "logs": cmd_logs,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
