#pragma once
/*
 * secure_download.h — Authenticated streaming download with AES-256-GCM decryption.
 *
 * Flow:
 *   1. POST /api/download-token → {token, aes_key, iv, tag, sha256, file_size}
 *   2. GET  /api/stream/<token>  → encrypted file bytes (server proxies from GitHub)
 *   3. Decrypt AES-256-GCM in memory, verify SHA-256
 *
 * Uses Windows BCrypt (built-in, no external libs) for AES-GCM.
 * Uses WinHTTP (same as self_auth.h) for network requests.
 */

#include <Windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <cstdio>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace SecureDownload {

// ── Hex decode ──────────────────────────────────────────────────────
static std::vector<uint8_t> HexDecode(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        char byte[3] = { hex[i], hex[i + 1], 0 };
        out.push_back((uint8_t)strtoul(byte, nullptr, 16));
    }
    return out;
}

// ── SHA-256 using BCrypt ────────────────────────────────────────────
static std::string Sha256Hex(const uint8_t* data, size_t len) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BYTE hash[32] = {};

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return "";

    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
    BCryptFinishHash(hHash, hash, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    char hex[65] = {};
    for (int i = 0; i < 32; i++)
        sprintf_s(hex + i * 2, 3, "%02x", hash[i]);
    return std::string(hex);
}

// ── AES-256-GCM Decrypt using Windows BCrypt ────────────────────────
// Input: ciphertext with appended 16-byte GCM auth tag (standard AEAD output)
// Returns true on success (tag verified), false on failure (tampered/wrong key)
static bool AesGcmDecrypt(
    const uint8_t* ciphertext_with_tag, size_t ct_tag_len,
    const uint8_t* key, size_t key_len,      // 32 bytes (AES-256)
    const uint8_t* iv,  size_t iv_len,       // 12 bytes (GCM nonce)
    std::vector<uint8_t>& plaintext)
{
    plaintext.clear();

    if (ct_tag_len < 16 || key_len != 32 || iv_len != 12)
        return false;

    size_t ct_len = ct_tag_len - 16;
    const uint8_t* tag = ciphertext_with_tag + ct_len;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != 0) return false;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PUCHAR)key, (ULONG)key_len, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Set up authenticated cipher mode info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = (ULONG)iv_len;
    authInfo.pbTag   = (PUCHAR)tag;
    authInfo.cbTag   = 16;
    authInfo.pbAuthData = nullptr;
    authInfo.cbAuthData = 0;

    // Determine output size
    ULONG ptLen = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext_with_tag, (ULONG)ct_len,
        &authInfo, nullptr, 0, nullptr, 0, &ptLen, 0);
    if (status != 0 && status != (NTSTATUS)0xC0000023L /* STATUS_BUFFER_TOO_SMALL */) {
        // For GCM, BCryptDecrypt with null output may return the ct_len directly
        ptLen = (ULONG)ct_len;
    }

    plaintext.resize(ptLen);

    // Reset auth info for actual decryption (BCrypt may modify internal state)
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = (ULONG)iv_len;
    authInfo.pbTag   = (PUCHAR)tag;
    authInfo.cbTag   = 16;
    authInfo.pbAuthData = nullptr;
    authInfo.cbAuthData = 0;

    ULONG written = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext_with_tag, (ULONG)ct_len,
        &authInfo, nullptr, 0, plaintext.data(), (ULONG)plaintext.size(), &written, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != 0) {
        // Auth tag verification failed — data tampered or wrong key
        SecureZeroMemory(plaintext.data(), plaintext.size());
        plaintext.clear();
        return false;
    }

    plaintext.resize(written);
    return true;
}

// ── JSON string extractor (same as self_auth.h) ────────────────────
static std::string ExtractJson(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    // Skip whitespace
    while (pos + 1 < json.size() && json[pos + 1] == ' ') pos++;
    // Check if value is a string or number
    size_t valStart = pos + 1;
    if (valStart >= json.size()) return "";
    if (json[valStart] == '"') {
        size_t end = json.find('"', valStart + 1);
        if (end == std::string::npos) return "";
        return json.substr(valStart + 1, end - valStart - 1);
    }
    // Number value
    size_t end = json.find_first_of(",}", valStart);
    if (end == std::string::npos) end = json.size();
    return json.substr(valStart, end - valStart);
}

// ── WinHTTP helpers ─────────────────────────────────────────────────
static std::wstring ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring ws(sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &ws[0], sz);
    return ws;
}

// POST JSON to auth server, returns response body
static std::string HttpPost(const std::string& host, int port,
                            const std::string& path, const std::string& body,
                            const std::string& hmacSecret)
{
    // Compute HMAC signature (same as self_auth.h)
    char tsBuf[32];
    sprintf_s(tsBuf, "%lld", (long long)time(nullptr));
    std::string timestamp(tsBuf);

    // HMAC-SHA256(secret, timestamp + body) using WinCrypt
    auto HmacSha256 = [](const std::string& key, const std::string& data) -> std::string {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HCRYPTKEY  hKey = 0;
        if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            return "";
        struct { BLOBHEADER hdr; DWORD keySize; BYTE keyData[256]; } blob = {};
        blob.hdr.bType = PLAINTEXTKEYBLOB;
        blob.hdr.bVersion = CUR_BLOB_VERSION;
        blob.hdr.aiKeyAlg = CALG_RC2;
        DWORD kLen = min((DWORD)key.size(), 256u);
        blob.keySize = kLen;
        memcpy(blob.keyData, key.c_str(), kLen);
        if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(BLOBHEADER) + sizeof(DWORD) + kLen, 0, CRYPT_IPSEC_HMAC_KEY, &hKey)) {
            CryptReleaseContext(hProv, 0); return "";
        }
        if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash)) {
            CryptDestroyKey(hKey); CryptReleaseContext(hProv, 0); return "";
        }
        HMAC_INFO hmacInfo = {}; hmacInfo.HashAlgid = CALG_SHA_256;
        CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0);
        CryptHashData(hHash, (const BYTE*)data.c_str(), (DWORD)data.size(), 0);
        BYTE hash[32]; DWORD hashLen = 32;
        CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
        CryptDestroyHash(hHash); CryptDestroyKey(hKey); CryptReleaseContext(hProv, 0);
        char hex[65] = {};
        for (DWORD i = 0; i < hashLen; i++) sprintf_s(hex + i * 2, 3, "%02x", hash[i]);
        return std::string(hex);
    };

    std::string sigData = timestamp + body;
    std::string signature = HmacSha256(hmacSecret, sigData);

    std::wstring wHost = ToWide(host);
    std::wstring wPath = ToWide(path);

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }

    WinHttpSetTimeouts(hRequest, 15000, 15000, 15000, 30000);

    std::wstring headers =
        L"Content-Type: application/json\r\n"
        L"X-Timestamp: " + ToWide(timestamp) + L"\r\n"
        L"X-Signature: " + ToWide(signature) + L"\r\n";

    BOOL sent = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.size(),
        (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);

    if (!sent || !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return "";
    }

    std::string result;
    DWORD bytesRead = 0;
    char buf[4096];
    while (WinHttpReadData(hRequest, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
        result.append(buf, bytesRead);
        bytesRead = 0;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

// GET binary data from auth server stream endpoint
static bool HttpGetBinary(const std::string& host, int port,
                          const std::string& path,
                          std::vector<uint8_t>& outBuffer)
{
    outBuffer.clear();
    std::wstring wHost = ToWide(host);
    std::wstring wPath = ToWide(path);

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    WinHttpSetTimeouts(hRequest, 15000, 15000, 30000, 120000);

    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!sent || !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return false;
    }

    // Check HTTP status code
    DWORD statusCode = 0, statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    if (statusCode != 200) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return false;
    }

    uint8_t buf[65536];
    DWORD bytesRead = 0;
    while (WinHttpReadData(hRequest, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
        outBuffer.insert(outBuffer.end(), buf, buf + bytesRead);
        bytesRead = 0;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return !outBuffer.empty();
}

// ── Key info returned by download-token endpoint ────────────────────
struct DownloadKeyInfo {
    std::string token;
    std::vector<uint8_t> aes_key;  // 32 bytes
    std::vector<uint8_t> iv;       // 12 bytes
    std::string expected_sha256;
    size_t file_size;
    bool valid;
};

// ── Request a download token from the auth server ───────────────────
static DownloadKeyInfo RequestDownloadToken(
    const std::string& host, int port, const std::string& hmacSecret,
    const std::string& sessionId, const std::string& build,
    const std::string& fileType, const std::string& hwid)
{
    DownloadKeyInfo info = {};
    info.valid = false;

    std::string json = "{\"session\":\"" + sessionId
        + "\",\"build\":\"" + build
        + "\",\"file\":\"" + fileType
        + "\",\"hwid\":\"" + hwid + "\"}";

    std::string resp = HttpPost(host, port, "/api/download-token", json, hmacSecret);
    if (resp.empty()) {
        printf("[ERROR] No response from auth server for download token\n");
        return info;
    }

    if (resp.find("\"success\":true") == std::string::npos &&
        resp.find("\"success\": true") == std::string::npos) {
        std::string msg = ExtractJson(resp, "message");
        printf("[ERROR] Download token denied: %s\n", msg.c_str());
        return info;
    }

    info.token          = ExtractJson(resp, "token");
    info.aes_key        = HexDecode(ExtractJson(resp, "aes_key"));
    info.iv             = HexDecode(ExtractJson(resp, "iv"));
    info.expected_sha256 = ExtractJson(resp, "sha256");

    std::string fileSizeStr = ExtractJson(resp, "file_size");
    info.file_size = fileSizeStr.empty() ? 0 : (size_t)_strtoui64(fileSizeStr.c_str(), nullptr, 10);

    if (info.token.empty() || info.aes_key.size() != 32 || info.iv.size() != 12) {
        printf("[ERROR] Invalid download token response\n");
        return info;
    }

    info.valid = true;
    return info;
}

// ── Full secure download: token → stream → decrypt → verify ─────────
// Returns decrypted plaintext in outBuffer. Returns false on any failure.
static bool SecureDownloadFile(
    const std::string& host, int port, const std::string& hmacSecret,
    const std::string& sessionId, const std::string& build,
    const std::string& fileType, const std::string& hwid,
    std::vector<uint8_t>& outBuffer)
{
    outBuffer.clear();

    // Step 1: Request download token + AES key
    printf("[*] Requesting download token for %s/%s...\n", build.c_str(), fileType.c_str());
    DownloadKeyInfo keyInfo = RequestDownloadToken(host, port, hmacSecret,
        sessionId, build, fileType, hwid);
    if (!keyInfo.valid) return false;

    // Step 2: Stream encrypted file from auth server
    printf("[*] Streaming encrypted %s from server...\n", fileType.c_str());
    std::string streamPath = "/api/stream/" + keyInfo.token;
    std::vector<uint8_t> encryptedData;
    if (!HttpGetBinary(host, port, streamPath, encryptedData)) {
        printf("[ERROR] Failed to stream encrypted file\n");
        return false;
    }
    printf("[+] Received %zu encrypted bytes\n", encryptedData.size());

    // Step 3: Decrypt AES-256-GCM
    printf("[*] Decrypting (AES-256-GCM)...\n");
    std::vector<uint8_t> plaintext;
    if (!AesGcmDecrypt(encryptedData.data(), encryptedData.size(),
                       keyInfo.aes_key.data(), keyInfo.aes_key.size(),
                       keyInfo.iv.data(), keyInfo.iv.size(),
                       plaintext)) {
        printf("[ERROR] Decryption failed — file tampered or wrong key\n");
        // Wipe encrypted data
        SecureZeroMemory(encryptedData.data(), encryptedData.size());
        return false;
    }

    // Wipe encrypted data and key material immediately
    SecureZeroMemory(encryptedData.data(), encryptedData.size());
    SecureZeroMemory(keyInfo.aes_key.data(), keyInfo.aes_key.size());
    SecureZeroMemory(keyInfo.iv.data(), keyInfo.iv.size());

    // Step 4: Verify SHA-256 integrity
    if (!keyInfo.expected_sha256.empty()) {
        std::string actualHash = Sha256Hex(plaintext.data(), plaintext.size());
        if (actualHash != keyInfo.expected_sha256) {
            printf("[ERROR] SHA-256 mismatch — file integrity compromised\n");
            printf("  Expected: %s\n", keyInfo.expected_sha256.c_str());
            printf("  Got:      %s\n", actualHash.c_str());
            SecureZeroMemory(plaintext.data(), plaintext.size());
            return false;
        }
    }

    // Step 5: Validate PE header
    if (plaintext.size() < 1024 || plaintext[0] != 'M' || plaintext[1] != 'Z') {
        printf("[ERROR] Decrypted data is not a valid PE file\n");
        SecureZeroMemory(plaintext.data(), plaintext.size());
        return false;
    }

    printf("[+] Decrypted and verified: %zu bytes (SHA-256 OK)\n", plaintext.size());
    outBuffer = std::move(plaintext);
    return true;
}

} // namespace SecureDownload
