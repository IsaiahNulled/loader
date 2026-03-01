# Secure File Delivery System

## Architecture Overview

```
┌─────────────┐     1. Auth (HMAC-signed)      ┌──────────────┐
│   Loader     │ ──────────────────────────────> │  Auth Server │
│   (C++)      │ <── session_id ──────────────── │  (Flask)     │
│              │                                 │              │
│              │  2. POST /api/download-token    │              │     ┌──────────┐
│              │ ──────────────────────────────> │              │     │  GitHub   │
│              │ <── {token, aes_key, iv, tag,   │              │     │  (storage)│
│              │      sha256, file_size}          │              │     │          │
│              │                                 │              │     │ .enc files│
│              │  3. GET /api/stream/<token>      │  proxies ──>│────>│          │
│              │ <── encrypted bytes ──────────── │  from GitHub │<────│          │
│              │                                 │              │     └──────────┘
│  4. Decrypt  │                                 └──────────────┘
│  AES-256-GCM │
│  Verify SHA  │
│  Execute     │
└─────────────┘
```

**Key principle**: The client NEVER contacts GitHub directly. The auth server acts as a proxy.

## Flow

### Build → Upload
1. Build safe + full binaries (driver.sys, User.exe, Loader.exe)
2. Run `deploy_secure.bat` which calls `encrypt_build.py --all`
3. Each binary is encrypted with a **unique** AES-256-GCM key + 12-byte nonce
4. Encrypted `.enc` files go to `C:\Users\Isaiah\Documents\repo\loader`
5. Key metadata (`build_keys.json`) stays on the auth server — never pushed to GitHub
6. Push encrypted repo via GitHub Desktop

### Client → Download
1. Loader authenticates → gets `session_id` (existing flow)
2. For each file (driver.sys, User.exe):
   - **POST** `/api/download-token` with `{session, build, file, hwid}`
   - Server validates session, HWID match, rate limits, returns:
     ```json
     {
       "token": "<single-use-64-char-hex>",
       "aes_key": "<32-byte-hex>",
       "iv": "<12-byte-hex>",
       "tag": "<16-byte-hex>",
       "sha256": "<plaintext-hash>",
       "file_size": 12345
     }
     ```
   - **GET** `/api/stream/<token>` — server validates token (single-use, 60s TTL), fetches `.enc` from GitHub, streams to client
   - Client decrypts AES-256-GCM in memory using Windows BCrypt API
   - Client verifies SHA-256 of decrypted plaintext
   - Client validates PE header (`MZ` + `PE\0\0`)

## Security Properties

| Property | Implementation |
|---|---|
| **No direct URLs** | Client talks only to auth server; server proxies from GitHub |
| **E2E encryption** | AES-256-GCM with per-file keys; files on GitHub are useless without keys |
| **Key separation** | Keys delivered via `/api/download-token` (over TLS); files via `/api/stream` |
| **Single-use tokens** | Token marked `used=1` on first stream request; 60s TTL |
| **HWID binding** | Token request verifies HWID matches authenticated session |
| **Rate limiting** | Max 10 downloads per session |
| **Anti-replay** | All HMAC-signed requests have timestamp within 30s window |
| **Integrity** | GCM auth tag (tamper detection) + SHA-256 (double verification) |
| **In-memory** | Decrypted PE never touches disk (User.exe); driver.sys written to temp, loaded, then securely deleted |
| **Key wiping** | `SecureZeroMemory` on key material + encrypted buffer after use |

## Files

### Backend (auth-server/)
- **`server.py`** — Auth server with new endpoints:
  - `POST /api/download-token` — Issues single-use token + delivers AES key
  - `GET /api/stream/<token>` — Validates token, proxies encrypted file from GitHub
  - `POST /api/admin/reload-keys` — Hot-reload build_keys.json without restart
- **`encrypt_build.py`** — Encrypts binaries with AES-256-GCM, outputs `.enc` files + `build_keys.json`
- **`build_keys.json`** — Per-build AES keys (server-side only, **NEVER commit to git**)

### Client (Loader/)
- **`secure_download.h`** — Complete secure download pipeline:
  - `RequestDownloadToken()` — HMAC-signed POST to get token + key
  - `HttpGetBinary()` — Stream encrypted bytes from server
  - `AesGcmDecrypt()` — Windows BCrypt AES-256-GCM decryption
  - `Sha256Hex()` — BCrypt SHA-256 for integrity verification
  - `SecureDownloadFile()` — Full pipeline: token → stream → decrypt → verify
- **`main.cpp`** — Updated `DownloadDriverToMemory` and `DownloadOverlayToMemory` to use secure download as primary, with direct GitHub as fallback

### Deploy Scripts
- **`deploy_secure.bat`** — Encrypts all builds + copies to repo (replaces `deploy_to_repo.bat`)
- **`deploy_to_repo.bat`** — Legacy: copies unencrypted binaries (fallback mode)

## Usage

### First-time setup
```bash
cd auth-server
pip install cryptography flask
```

### Deploy new builds
```bat
REM Build everything in Visual Studio first, then:
deploy_secure.bat
REM Push via GitHub Desktop
REM Restart auth server (or call POST /api/admin/reload-keys)
```

### Server requirements
- `build_keys.json` must be present alongside `server.py`
- Server needs outbound HTTPS to `raw.githubusercontent.com` for proxying
- `pip install cryptography` only needed on the build machine (for encryption)

## Fallback Behavior
If secure download fails (server unreachable, keys not loaded, etc.), the Loader falls back to direct GitHub download of **unencrypted** files. This ensures the loader still works during the transition period. Once fully migrated, remove the fallback code and keep only encrypted files on GitHub.
