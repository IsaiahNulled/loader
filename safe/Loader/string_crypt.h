#pragma once
/*
 * string_crypt.h — Multi-layer compile-time string encryption
 *
 * Replaces skCrypt with a stronger, less recognizable system.
 * - Triple-pass encryption (XOR → ADD → XOR) with unique per-string keys
 * - Key derivation via FNV-1a hash, not predictable __TIME__ chars
 * - RAII auto-wipe: decrypted strings zeroed on scope exit
 * - URL fragment assembly: URLs split into parts, assembled at runtime
 * - Wide string support for wchar_t paths
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <windows.h>

namespace enc {

// ── Compile-time pseudo-random key derivation ──────────────────────
constexpr uint32_t fnv1a(uint32_t h, uint32_t val) {
    h ^= (val & 0xFF); h *= 0x01000193u;
    h ^= ((val >> 8) & 0xFF); h *= 0x01000193u;
    h ^= ((val >> 16) & 0xFF); h *= 0x01000193u;
    h ^= ((val >> 24) & 0xFF); h *= 0x01000193u;
    return h;
}

constexpr uint8_t keybyte(uint32_t seed, size_t idx, uint32_t salt) {
    uint32_t h = seed ^ static_cast<uint32_t>(idx) ^ salt;
    h = ((h >> 16) ^ h) * 0x45D9F3Bu;
    h = ((h >> 16) ^ h) * 0x45D9F3Bu;
    h = (h >> 16) ^ h;
    return static_cast<uint8_t>(h);
}

// ── Compile-time encrypted char array ─────────────────────────────
template<size_t N, uint32_t Seed>
class Encrypted {
public:
    constexpr Encrypted(const char(&src)[N]) : buf_{} {
        for (size_t i = 0; i < N; ++i) {
            uint8_t b = static_cast<uint8_t>(src[i]);
            b ^= keybyte(Seed, i, 0x1F2E3D4Cu);           // pass 1
            b  = static_cast<uint8_t>(b + keybyte(Seed, i, 0xA1B2C3D4u)); // pass 2
            b ^= keybyte(Seed, N - 1 - i, 0x5E6F7A8Bu);   // pass 3
            buf_[i] = b;
        }
    }

    std::string get() const {
        char tmp[N];
        for (size_t i = 0; i < N; ++i) {
            uint8_t b = buf_[i];
            b ^= keybyte(Seed, N - 1 - i, 0x5E6F7A8Bu);   // undo pass 3
            b  = static_cast<uint8_t>(b - keybyte(Seed, i, 0xA1B2C3D4u)); // undo pass 2
            b ^= keybyte(Seed, i, 0x1F2E3D4Cu);           // undo pass 1
            tmp[i] = static_cast<char>(b);
        }
        std::string result(tmp, N - 1); // exclude null terminator
        SecureZeroMemory(tmp, N);
        return result;
    }

private:
    uint8_t buf_[N];
};

// ── Compile-time encrypted wchar_t array ──────────────────────────
template<size_t N, uint32_t Seed>
class EncryptedW {
public:
    constexpr EncryptedW(const wchar_t(&src)[N]) : buf_{} {
        for (size_t i = 0; i < N; ++i) {
            uint16_t w = static_cast<uint16_t>(src[i]);
            uint8_t lo = static_cast<uint8_t>(w & 0xFF);
            uint8_t hi = static_cast<uint8_t>((w >> 8) & 0xFF);
            lo ^= keybyte(Seed, i * 2, 0x1F2E3D4Cu);
            lo  = static_cast<uint8_t>(lo + keybyte(Seed, i * 2, 0xA1B2C3D4u));
            hi ^= keybyte(Seed, i * 2 + 1, 0x1F2E3D4Cu);
            hi  = static_cast<uint8_t>(hi + keybyte(Seed, i * 2 + 1, 0xA1B2C3D4u));
            buf_[i * 2]     = lo;
            buf_[i * 2 + 1] = hi;
        }
    }

    std::wstring get() const {
        wchar_t tmp[N];
        for (size_t i = 0; i < N; ++i) {
            uint8_t lo = buf_[i * 2];
            uint8_t hi = buf_[i * 2 + 1];
            hi  = static_cast<uint8_t>(hi - keybyte(Seed, i * 2 + 1, 0xA1B2C3D4u));
            hi ^= keybyte(Seed, i * 2 + 1, 0x1F2E3D4Cu);
            lo  = static_cast<uint8_t>(lo - keybyte(Seed, i * 2, 0xA1B2C3D4u));
            lo ^= keybyte(Seed, i * 2, 0x1F2E3D4Cu);
            tmp[i] = static_cast<wchar_t>(lo | (hi << 8));
        }
        std::wstring result(tmp, N - 1);
        SecureZeroMemory(tmp, sizeof(tmp));
        return result;
    }

private:
    uint8_t buf_[N * 2];
};

// ── RAII wrapper: auto-wipes string on destruction ────────────────
class SecureString {
public:
    SecureString(std::string s) : str_(std::move(s)) {}
    ~SecureString() {
        if (!str_.empty()) {
            SecureZeroMemory(&str_[0], str_.size());
        }
    }
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    SecureString(SecureString&& o) noexcept : str_(std::move(o.str_)) {}

    const std::string& s() const { return str_; }
    const char* c() const { return str_.c_str(); }
    operator const std::string&() const { return str_; }
    operator const char*() const { return str_.c_str(); }
private:
    std::string str_;
};

class SecureWString {
public:
    SecureWString(std::wstring s) : str_(std::move(s)) {}
    ~SecureWString() {
        if (!str_.empty()) {
            SecureZeroMemory(&str_[0], str_.size() * sizeof(wchar_t));
        }
    }
    SecureWString(const SecureWString&) = delete;
    SecureWString& operator=(const SecureWString&) = delete;
    SecureWString(SecureWString&& o) noexcept : str_(std::move(o.str_)) {}

    const std::wstring& s() const { return str_; }
    const wchar_t* c() const { return str_.c_str(); }
    operator const std::wstring&() const { return str_; }
    operator const wchar_t*() const { return str_.c_str(); }
private:
    std::wstring str_;
};

// ── URL builder: assembles URL from encrypted fragments at runtime ─
inline std::string BuildUrl(std::initializer_list<std::string> parts) {
    std::string url;
    url.reserve(256);
    for (auto& p : parts) url += p;
    return url;
}

} // namespace enc

// ── Main macros ───────────────────────────────────────────────────
// Each invocation gets a unique compile-time seed from __LINE__ + __COUNTER__
// so no two strings share keys, and the pattern is never the same.

#define _ENC_SEED ((__LINE__ * 0x7E3Au) ^ (__COUNTER__ * 0xB5C1u) ^ 0xD4E5F6A7u)

// Decrypt a compile-time encrypted narrow string → std::string
#define E(str) ([]() -> std::string { \
    constexpr static ::enc::Encrypted<sizeof(str), _ENC_SEED> _e(str); \
    return _e.get(); \
}())

// Decrypt a compile-time encrypted wide string → std::wstring
#define EW(str) ([]() -> std::wstring { \
    constexpr static ::enc::EncryptedW<sizeof(str)/sizeof(wchar_t), _ENC_SEED> _e(str); \
    return _e.get(); \
}())

// Secure variants: RAII wrappers that auto-zero on scope exit
#define ES(str) (::enc::SecureString(E(str)))
#define EWS(str) (::enc::SecureWString(EW(str)))
