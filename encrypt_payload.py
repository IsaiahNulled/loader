"""
XOR encrypt binaries before uploading to GitHub.
Uses the same key as the loaders: "NulledX!" (0x4E 0x75 0x6C 0x6C 0x65 0x64 0x58 0x21)
"""
import sys
import os

KEY = bytes([0x4E, 0x75, 0x6C, 0x6C, 0x65, 0x64, 0x58, 0x21])  # "NulledX!"

def xor_encrypt(data: bytes) -> bytes:
    key_len = len(KEY)
    return bytes(b ^ KEY[i % key_len] for i, b in enumerate(data))

def encrypt_file(input_path: str, output_path: str):
    with open(input_path, 'rb') as f:
        data = f.read()
    
    encrypted = xor_encrypt(data)
    
    with open(output_path, 'wb') as f:
        f.write(encrypted)
    
    print(f"  Encrypted: {input_path}")
    print(f"    -> {output_path} ({len(data)} bytes)")

if __name__ == "__main__":
    if len(sys.argv) == 3:
        encrypt_file(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python encrypt_payload.py <input_file> <output_file>")
        print("  Encrypts a binary file with XOR key 'NulledX!'")
