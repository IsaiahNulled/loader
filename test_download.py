#!/usr/bin/env python3
"""
test_download.py - Test the secure download flow to debug User.exe issues
"""

import requests
import json
import hashlib
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Server config
HOST = "73.137.88.21"
PORT = 7777
BASE_URL = f"http://{HOST}:{PORT}"

# Test credentials (use a valid test key)
TEST_KEY = "test-key-123"
HMAC_SECRET = "x9K#mP2$vL8nQ4wR7jT0yF5bN3hA6cD1"

def make_hmac(secret: str, timestamp: str, body: str) -> str:
    import hmac
    import hashlib
    return hmac.new(
        secret.encode(),
        (timestamp + body).encode(),
        hashlib.sha256
    ).hexdigest()

def test_auth():
    """Test authentication flow"""
    print("=== Testing Authentication ===")
    
    # Get session
    auth_data = {
        "key": TEST_KEY,
        "hwid": "test-hwid-12345"
    }
    
    ts = str(int(time.time()))
    body = json.dumps(auth_data)
    sig = make_hmac(HMAC_SECRET, ts, body)
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/auth",
            json=auth_data,
            headers={
                "X-Signature": sig,
                "X-Timestamp": ts
            },
            timeout=10
        )
        
        print(f"Auth response: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                session_id = data.get("session")
                print(f"[+] Auth successful, session: {session_id}")
                return session_id
            else:
                print(f"[-] Auth failed: {data.get('message')}")
        else:
            print(f"[-] Auth error: {response.text}")
    except Exception as e:
        print(f"[-] Auth exception: {e}")
    
    return None

def test_download_token(session_id: str):
    """Test download token issuance"""
    print("\n=== Testing Download Token ===")
    
    download_data = {
        "session": session_id,
        "build": "full",
        "file": "user",
        "hwid": "test-hwid-12345"
    }
    
    ts = str(int(time.time()))
    body = json.dumps(download_data)
    sig = make_hmac(HMAC_SECRET, ts, body)
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/download-token",
            json=download_data,
            headers={
                "X-Signature": sig,
                "X-Timestamp": ts
            },
            timeout=10
        )
        
        print(f"Token response: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                token_info = {
                    "token": data.get("token"),
                    "aes_key": data.get("aes_key"),
                    "iv": data.get("iv"),
                    "tag": data.get("tag"),
                    "sha256": data.get("sha256"),
                    "file_size": data.get("file_size")
                }
                print(f"[+] Token issued, file size: {token_info['file_size']}")
                return token_info
            else:
                print(f"[-] Token failed: {data.get('message')}")
        else:
            print(f"[-] Token error: {response.text}")
    except Exception as e:
        print(f"[-] Token exception: {e}")
    
    return None

def test_download_stream(token_info: dict):
    """Test encrypted file download and decryption"""
    print("\n=== Testing Encrypted Download ===")
    
    try:
        # Download encrypted file
        response = requests.get(
            f"{BASE_URL}/api/stream/{token_info['token']}",
            timeout=30
        )
        
        print(f"Stream response: {response.status_code}")
        if response.status_code != 200:
            print(f"[-] Stream failed: {response.text}")
            return False
        
        encrypted_data = response.content
        print(f"Downloaded {len(encrypted_data)} bytes")
        
        # Decrypt with AES-GCM
        aes_key = bytes.fromhex(token_info['aes_key'])
        iv = bytes.fromhex(token_info['iv'])
        tag = bytes.fromhex(token_info['tag'])
        
        aesgcm = AESGCM(aes_key)
        
        try:
            decrypted_data = aesgcm.decrypt(iv, encrypted_data + tag, None)
            print(f"[+] Decrypted {len(decrypted_data)} bytes")
            
            # Check PE signature
            if len(decrypted_data) >= 2 and decrypted_data[0] == 0x4D and decrypted_data[1] == 0x5A:
                print("[+] Valid PE signature (MZ)")
                
                # Verify SHA-256
                calculated_hash = hashlib.sha256(decrypted_data).hexdigest()
                expected_hash = token_info['sha256']
                
                if calculated_hash == expected_hash:
                    print("[+] SHA-256 verification passed")
                    return True
                else:
                    print(f"[-] SHA-256 mismatch: {calculated_hash} != {expected_hash}")
            else:
                print(f"[-] Invalid PE signature: {decrypted_data[:2].hex() if len(decrypted_data) >= 2 else 'too short'}")
                
        except Exception as decrypt_error:
            print(f"[-] Decryption failed: {decrypt_error}")
            
    except Exception as e:
        print(f"[-] Download exception: {e}")
    
    return False

def main():
    print("Testing secure download flow...")
    print(f"Server: {BASE_URL}")
    
    session_id = test_auth()
    if not session_id:
        print("[-] Authentication failed, aborting")
        return
    
    token_info = test_download_token(session_id)
    if not token_info:
        print("[-] Token issuance failed, aborting")
        return
    
    success = test_download_stream(token_info)
    if success:
        print("\n[+] Full download test PASSED - User.exe should work!")
    else:
        print("\n[-] Download test FAILED - User.exe will be corrupted")

if __name__ == "__main__":
    main()
