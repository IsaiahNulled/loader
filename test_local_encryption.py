#!/usr/bin/env python3
"""
test_local_encryption.py - Test local encryption/decryption to verify User.exe integrity
"""

import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def test_local_files():
    """Test the local encrypted files and keys"""
    print("=== Testing Local Encryption Files ===")
    
    # Paths
    auth_dir = r"C:\Users\Isaiah\Desktop\external\auth-server"
    repo_dir = r"C:\Users\Isaiah\Documents\repo\loader"
    
    keys_file = os.path.join(auth_dir, "build_keys.json")
    
    # Load keys
    if not os.path.exists(keys_file):
        print("[-] build_keys.json not found")
        return False
    
    with open(keys_file, 'r') as f:
        keys = json.load(f)
    
    print(f"[+] Loaded keys for builds: {list(keys.keys())}")
    
    # Test each build
    for build in ['full', 'safe']:
        print(f"\n--- Testing {build} build ---")
        
        build_keys = keys.get(build, {})
        user_key_info = build_keys.get('user')
        
        if not user_key_info:
            print(f"[-] No user key info for {build}")
            continue
        
        # Check encrypted file
        enc_file = os.path.join(repo_dir, f"{build}/User.exe.enc")
        if not os.path.exists(enc_file):
            print(f"[-] Encrypted file not found: {enc_file}")
            continue
        
        # Read encrypted file
        with open(enc_file, 'rb') as f:
            encrypted_data = f.read()
        
        print(f"[+] Read {len(encrypted_data)} bytes from {enc_file}")
        
        # Decrypt
        try:
            aes_key = bytes.fromhex(user_key_info['key'])
            iv = bytes.fromhex(user_key_info['iv'])
            tag = bytes.fromhex(user_key_info['tag'])
            
            aesgcm = AESGCM(aes_key)
            # The encrypted file contains ciphertext + tag (16 bytes) concatenated
            # This is exactly what encrypt_file() stores as "encrypted_blob"
            decrypted_data = aesgcm.decrypt(iv, encrypted_data, None)
            
            print(f"[+] Decrypted {len(decrypted_data)} bytes")
            
            # Check PE signature
            if len(decrypted_data) >= 2 and decrypted_data[0] == 0x4D and decrypted_data[1] == 0x5A:
                print("[+] Valid PE signature (MZ)")
                
                # Verify SHA-256
                calculated_hash = hashlib.sha256(decrypted_data).hexdigest()
                expected_hash = user_key_info['sha256']
                
                if calculated_hash == expected_hash:
                    print("[+] SHA-256 verification passed")
                    
                    # Check file size
                    expected_size = user_key_info['plaintext_size']
                    if len(decrypted_data) == expected_size:
                        print(f"[+] File size matches: {len(decrypted_data)} bytes")
                        
                        # Check for overlay UI indicators (basic check)
                        exe_content = decrypted_data[:1000]  # Check first 1KB
                        if b'overlay' in exe_content.lower() or b'directx' in exe_content.lower() or b'd3d' in exe_content.lower():
                            print("[+] Contains overlay-related strings")
                        else:
                            print("[?] No obvious overlay strings found (might be obfuscated)")
                        
                        return True
                    else:
                        print(f"[-] Size mismatch: got {len(decrypted_data)}, expected {expected_size}")
                else:
                    print(f"[-] SHA-256 mismatch")
                    print(f"    Calculated: {calculated_hash}")
                    print(f"    Expected:   {expected_hash}")
            else:
                print(f"[-] Invalid PE signature: {decrypted_data[:2].hex() if len(decrypted_data) >= 2 else 'too short'}")
                
        except Exception as e:
            print(f"[-] Decryption failed: {e}")
            print(f"    Key length: {len(aes_key)} bytes")
            print(f"    IV length: {len(iv)} bytes") 
            print(f"    Tag length: {len(tag)} bytes")
            print(f"    Data length: {len(encrypted_data)} bytes")
            print(f"    Expected size: {user_key_info['plaintext_size']} bytes")
            
            # Try to see what the file tag is
            if len(encrypted_data) >= 16:
                file_tag = encrypted_data[-16:]
                print(f"    File tag: {file_tag.hex()}")
                print(f"    Expected tag: {tag.hex()}")
    
    return False

def test_xor_encryption():
    """Test XOR-encrypted Loader.exe files"""
    print("\n=== Testing XOR Encryption ===")
    
    repo_dir = r"C:\Users\Isaiah\Documents\repo\loader"
    
    # XOR key from encrypt_build.py
    xor_key = bytes([
        0x7A, 0x3F, 0xB2, 0xE1, 0x5C, 0x8D, 0x4E, 0xF0,
        0x1B, 0xA9, 0x63, 0xD7, 0x2E, 0x95, 0x48, 0xC6,
        0x0F, 0x84, 0x71, 0xBA, 0x3D, 0xE8, 0x56, 0x9C,
        0x27, 0xF5, 0x6A, 0xD3, 0x1E, 0x89, 0x44, 0xB7,
    ])
    
    def stream_crypt(data):
        """Custom stream cipher (same as encrypt_build.py)"""
        key_len = len(xor_key)
        S = list(range(256))
        
        # Key scheduling
        j = 0
        for rnd in range(4):
            for i in range(256):
                j = (j + S[i] + xor_key[(i + rnd) % key_len]) & 0xFF
                S[i], S[j] = S[j], S[i]
        
        # Generate keystream
        i = 0
        j = 0
        output = bytearray(len(data))
        for n in range(len(data)):
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) & 0xFF]
            k = (k ^ ((n * 0x9E) & 0xFF)) & 0xFF
            output[n] = data[n] ^ k
        
        return bytes(output)
    
    for build in ['full', 'safe']:
        print(f"\n--- Testing {build} XOR Loader.exe ---")
        
        loader_file = os.path.join(repo_dir, f"{build}/Loader.exe")
        if not os.path.exists(loader_file):
            print(f"[-] Loader.exe not found: {loader_file}")
            continue
        
        with open(loader_file, 'rb') as f:
            xor_data = f.read()
        
        print(f"[+] Read {len(xor_data)} bytes from {loader_file}")
        
        # Decrypt
        try:
            decrypted = stream_crypt(xor_data)
            print(f"[+] Decrypted {len(decrypted)} bytes")
            
            # Check PE signature
            if len(decrypted) >= 2 and decrypted[0] == 0x4D and decrypted[1] == 0x5A:
                print("[+] Valid PE signature after XOR decryption")
                print(f"[+] First 16 bytes: {decrypted[:16].hex()}")
            else:
                print(f"[-] Invalid PE signature: {decrypted[:2].hex() if len(decrypted) >= 2 else 'too short'}")
                print(f"[-] First 16 bytes: {decrypted[:16].hex() if len(decrypted) >= 16 else 'insufficient data'}")
                
                # Check if it's still encrypted (maybe wrong key)
                if decrypted[0] == 0x94 and decrypted[1] == 0xED:
                    print("[-] Still encrypted - key mismatch or wrong algorithm")
                
        except Exception as e:
            print(f"[-] XOR decryption failed: {e}")

def main():
    print("Testing local encryption integrity...")
    
    success = test_local_files()
    test_xor_encryption()
    
    if success:
        print("\n[+] Local encryption test PASSED")
        print("    If User.exe still doesn't work in-game, the issue might be:")
        print("    1. Server needs restart to reload new keys")
        print("    2. Network/firewall blocking secure downloads")
        print("    3. Overlay crashing due to missing dependencies")
        print("    4. Anti-virus blocking the overlay process")
    else:
        print("\n[-] Local encryption test FAILED")
        print("    The User.exe files are corrupted or keys don't match")

if __name__ == "__main__":
    main()
