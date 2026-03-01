#!/usr/bin/env python3
"""
encrypt_build.py — Encrypt build binaries with AES-256-GCM before uploading.

Usage:
    python encrypt_build.py --all
        Encrypts all 6 binaries (safe+full × driver+user+loader),
        writes .enc files to the repo folder, and saves keys to build_keys.json.

    python encrypt_build.py --input <file> --build <safe|full> --file-type <driver|user|loader>
        Encrypt a single file.

Requires: pip install cryptography
"""

import os
import sys
import json
import hashlib
import secrets
import argparse
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("[!] Missing dependency: pip install cryptography")
    sys.exit(1)

# ── Paths ────────────────────────────────────────────────────────────
SCRIPT_DIR  = Path(__file__).parent.resolve()
KEYS_FILE   = SCRIPT_DIR / "build_keys.json"

# Build source directory (where compiled binaries live)
BUILD_SRC   = Path(r"C:\Users\Isaiah\Desktop\external")

# Repo directory (where encrypted blobs go for GitHub push)
REPO_DIR    = Path(r"C:\Users\Isaiah\Desktop\external")

# Map of (build, file_type) → relative source path from BUILD_SRC
SOURCE_MAP = {
    ("full", "loader"):  "full/Loader/x64/Release/Loader.exe",
    ("full", "user"):    "full/User/x64/Release/User.exe",
    ("full", "driver"):  "full/driver/x64/Release/driver.sys",
    ("safe", "loader"):  "safe/Loader/x64/Release/Loader.exe",
    ("safe", "user"):    "safe/User/x64/Release/User.exe",
    ("safe", "driver"):  "safe/driver/x64/Release/driver.sys",
}

# Map of (build, file_type) → repo output filename
REPO_MAP = {
    ("full", "loader"):  "full/Loader.exe.enc",
    ("full", "user"):    "full/User.exe.enc",
    ("full", "driver"):  "full/driver.sys.enc",
    ("safe", "loader"):  "safe/Loader.exe.enc",
    ("safe", "user"):    "safe/User.exe.enc",
    ("safe", "driver"):  "safe/driver.sys.enc",
}


# Custom stream cipher key — 32 bytes (must match FrontLoader's PAYLOAD_KEY)
# This is NOT simple XOR. Uses RC4-like S-box with multi-round key schedule.
PAYLOAD_KEY = bytes([
    0x7A, 0x3F, 0xB2, 0xE1, 0x5C, 0x8D, 0x4E, 0xF0,
    0x1B, 0xA9, 0x63, 0xD7, 0x2E, 0x95, 0x48, 0xC6,
    0x0F, 0x84, 0x71, 0xBA, 0x3D, 0xE8, 0x56, 0x9C,
    0x27, 0xF5, 0x6A, 0xD3, 0x1E, 0x89, 0x44, 0xB7,
])


def custom_stream_encrypt(data: bytes, key: bytes) -> bytes:
    """Custom stream cipher — S-box based, 4-round key schedule, position-dependent mixing.
    Symmetric: encrypt(encrypt(data)) != data, but encrypt and decrypt use same function
    because the keystream XOR is the same both ways."""
    key_len = len(key)

    # Initialize S-box (permutation table)
    S = list(range(256))

    # Key scheduling — 4 rounds of S-box shuffling
    j = 0
    for rnd in range(4):
        for i in range(256):
            j = (j + S[i] + key[(i + rnd) % key_len]) & 0xFF
            S[i], S[j] = S[j], S[i]

    # Generate keystream and encrypt
    i = 0
    j = 0
    output = bytearray(len(data))
    for n in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        k = (k ^ ((n * 0x9E) & 0xFF)) & 0xFF  # Position-dependent mixing
        output[n] = data[n] ^ k

    return bytes(output)


def encrypt_file(plaintext: bytes) -> dict:
    """Encrypt plaintext with AES-256-GCM. Returns dict with key, iv, tag, ciphertext, sha256."""
    key = secrets.token_bytes(32)   # AES-256
    iv  = secrets.token_bytes(12)   # GCM standard 96-bit nonce

    sha256 = hashlib.sha256(plaintext).hexdigest()

    aesgcm = AESGCM(key)
    # encrypt() returns ciphertext || 16-byte auth tag
    ct_with_tag = aesgcm.encrypt(iv, plaintext, None)

    ct  = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    return {
        "key_hex":         key.hex(),
        "iv_hex":          iv.hex(),
        "tag_hex":         tag.hex(),
        "sha256":          sha256,
        "plaintext_size":  len(plaintext),
        "encrypted_blob":  ct_with_tag,  # full blob to write (ct + tag)
    }


def load_keys() -> dict:
    if KEYS_FILE.exists():
        with open(KEYS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_keys(keys: dict):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)
    print(f"  [+] Keys saved to {KEYS_FILE}")


def process_one(build: str, file_type: str, input_path: Path = None):
    """Encrypt one binary, write .enc to repo, update keys."""
    if input_path is None:
        rel = SOURCE_MAP.get((build, file_type))
        if not rel:
            print(f"  [!] Unknown build/file_type: {build}/{file_type}")
            return None
        input_path = BUILD_SRC / rel

    if not input_path.exists():
        print(f"  [!] Source not found: {input_path}")
        return None

    print(f"  [*] Encrypting {build}/{file_type}: {input_path.name} ({input_path.stat().st_size:,} bytes)")

    plaintext = input_path.read_bytes()
    result = encrypt_file(plaintext)

    # Write encrypted blob to repo
    repo_rel = REPO_MAP.get((build, file_type))
    if not repo_rel:
        print(f"  [!] No repo mapping for {build}/{file_type}")
        return None

    out_path = REPO_DIR / repo_rel
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(result["encrypted_blob"])
    print(f"  [+] Wrote {out_path} ({len(result['encrypted_blob']):,} bytes)")

    # Return key metadata (no blob)
    return {
        "key":            result["key_hex"],
        "iv":             result["iv_hex"],
        "tag":            result["tag_hex"],
        "sha256":         result["sha256"],
        "plaintext_size": result["plaintext_size"],
        "encrypted_size": len(result["encrypted_blob"]),
    }


def xor_encrypt_loader(build: str):
    """XOR-encrypt Loader.exe for FrontLoader compatibility.
    
    The FrontLoader downloads Loader.exe (not .enc) from GitHub and
    XOR-decrypts it with the 'NulledX!' key. So we must XOR-encrypt
    before uploading.
    """
    rel = SOURCE_MAP.get((build, "loader"))
    if not rel:
        return
    input_path = BUILD_SRC / rel
    if not input_path.exists():
        print(f"  [!] Loader not found for XOR: {input_path}")
        return

    plaintext = input_path.read_bytes()
    encrypted = custom_stream_encrypt(plaintext, PAYLOAD_KEY)

    # Write XOR-encrypted Loader.exe (NOT .enc) to repo
    out_path = REPO_DIR / build / "Loader.exe"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(encrypted)
    print(f"  [+] XOR-encrypted {build}/Loader.exe ({len(encrypted):,} bytes) for FrontLoader")


def encrypt_all():
    """Encrypt all 6 binaries."""
    keys = load_keys()

    print("\n  ==========================================")
    print("   Encrypting all builds (AES-256-GCM)")
    print("  ==========================================\n")

    for (build, file_type) in SOURCE_MAP:
        meta = process_one(build, file_type)
        if meta:
            if build not in keys:
                keys[build] = {}
            keys[build][file_type] = meta
            print()

    save_keys(keys)

    # Also XOR-encrypt Loader.exe for FrontLoader compatibility
    print("  ------------------------------------------")
    print("  XOR-encrypting Loader.exe for FrontLoader:")
    for build in ("full", "safe"):
        xor_encrypt_loader(build)

    print("\n  ==========================================")
    print("   Done! Push repo via GitHub Desktop.")
    print("   Keys are in build_keys.json (server-side only).")
    print("  ==========================================\n")


def main():
    parser = argparse.ArgumentParser(description="Encrypt build binaries with AES-256-GCM")
    parser.add_argument("--all", action="store_true", help="Encrypt all builds")
    parser.add_argument("--input", type=str, help="Input file path")
    parser.add_argument("--build", type=str, choices=["safe", "full"], help="Build type")
    parser.add_argument("--file-type", type=str, choices=["driver", "user", "loader"], help="File type")
    args = parser.parse_args()

    if args.all:
        encrypt_all()
    elif args.input and args.build and args.file_type:
        keys = load_keys()
        meta = process_one(args.build, args.file_type, Path(args.input))
        if meta:
            if args.build not in keys:
                keys[args.build] = {}
            keys[args.build][args.file_type] = meta
            save_keys(keys)
    else:
        parser.print_help()
        print("\n  Example: python encrypt_build.py --all")


if __name__ == "__main__":
    main()
