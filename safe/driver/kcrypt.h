#pragma once
/*
 * kcrypt.h — Compile-time string obfuscation for WDM kernel drivers
 *
 * All strings are XOR-encrypted in .rdata at compile time and decrypted
 * on the stack at runtime. Stack buffers are zeroed on scope exit.
 *
 * Requirements: MSVC C++14 or later (constexpr loops)
 *
 * Usage:
 *   KC_ANSI(myVar, "dxgkrnl.sys");       // decrypts into char myVar[]
 *   KC_WIDE(myVar, L"NtOpenFile");        // decrypts into wchar_t myVar[]
 *   // myVar is usable as const char* / const wchar_t*
 *   // auto-zeroed when myVar goes out of scope (RAII destructor)
 */

namespace kc {

// ── Key derivation ─────────────────────────────────────────────────
// Position-dependent byte key: different XOR mask for every character index
static __forceinline constexpr unsigned char kb(unsigned seed, int i) {
    return (unsigned char)(((seed >> (i & 7)) ^ (i * 131u + 17u) ^ (seed * 37u)) & 0xFF);
}
static __forceinline constexpr unsigned short kw(unsigned seed, int i) {
    return (unsigned short)(((seed >> (i & 7)) ^ (i * 131u + 17u) ^ (seed * 37u)) & 0xFFFF);
}

// ── Compile-time encrypted ANSI string ─────────────────────────────
template<int N, unsigned Seed>
struct EncA {
    char d[N];
    constexpr EncA(const char (&s)[N]) : d{} {
        for (int i = 0; i < N; i++)
            d[i] = s[i] ^ (char)kb(Seed, i);
    }
};

// ── Runtime decryptor for ANSI (stack-allocated, auto-zeroed) ──────
template<int N, unsigned Seed>
struct DecA {
    char b[N];
    __forceinline DecA(const EncA<N, Seed>& e) {
        for (int i = 0; i < N; i++)
            b[i] = e.d[i] ^ (char)kb(Seed, i);
    }
    __forceinline ~DecA() {
        volatile char* p = b;
        for (int i = 0; i < N; i++) p[i] = 0;
    }
    __forceinline operator const char*() const { return b; }
};

// ── Compile-time encrypted wide string ─────────────────────────────
template<int N, unsigned Seed>
struct EncW {
    wchar_t d[N];
    constexpr EncW(const wchar_t (&s)[N]) : d{} {
        for (int i = 0; i < N; i++)
            d[i] = s[i] ^ (wchar_t)kw(Seed, i);
    }
};

// ── Runtime decryptor for wide (stack-allocated, auto-zeroed) ──────
template<int N, unsigned Seed>
struct DecW {
    wchar_t b[N];
    __forceinline DecW(const EncW<N, Seed>& e) {
        for (int i = 0; i < N; i++)
            b[i] = e.d[i] ^ (wchar_t)kw(Seed, i);
    }
    __forceinline ~DecW() {
        volatile wchar_t* p = b;
        for (int i = 0; i < N; i++) p[i] = 0;
    }
    __forceinline operator const wchar_t*() const { return b; }
};

} // namespace kc

// ── Per-line seed: unique encryption key per source line ───────────
#define _KC_SEED ((__LINE__ * 0x7E3Au + 0xB5C1u) ^ 0x4D2F1A83u)

// ── Main macros ────────────────────────────────────────────────────
// KC_ANSI(varname, "string")  — creates stack-decrypted char[] named varname
// KC_WIDE(varname, L"string") — creates stack-decrypted wchar_t[] named varname
//
// The encrypted data lives in .rdata (constexpr static).
// The decrypted buffer lives on the current stack frame.
// When varname goes out of scope, the stack buffer is zeroed.

#define KC_ANSI(name, str) \
    constexpr static kc::EncA<sizeof(str), _KC_SEED> _kce_##name(str); \
    kc::DecA<sizeof(str), _KC_SEED> name(_kce_##name)

#define KC_WIDE(name, str) \
    constexpr static kc::EncW<sizeof(str)/sizeof(wchar_t), _KC_SEED> _kce_##name(str); \
    kc::DecW<sizeof(str)/sizeof(wchar_t), _KC_SEED> name(_kce_##name)

// ── Hook state encryption ──────────────────────────────────────────
// Runtime XOR key for sensitive global state (PTE hook data, etc.)
// Generated once at driver init from performance counter + TSC
namespace kc {

static volatile ULONG64 g_StateKey = 0;

static __forceinline void InitStateKey() {
    LARGE_INTEGER perf = KeQueryPerformanceCounter(NULL);
    ULONG64 tsc = __rdtsc();
    g_StateKey = perf.QuadPart ^ tsc ^ 0xA5A5A5A5A5A5A5A5ULL;
    if (!g_StateKey) g_StateKey = 0xDEADC0DE13371337ULL;
}

static __forceinline ULONG64 EncryptU64(ULONG64 val) {
    return val ^ g_StateKey;
}

static __forceinline ULONG64 DecryptU64(ULONG64 val) {
    return val ^ g_StateKey;
}

static __forceinline PVOID EncryptPtr(PVOID val) {
    return (PVOID)((ULONG_PTR)val ^ (ULONG_PTR)g_StateKey);
}

static __forceinline PVOID DecryptPtr(PVOID val) {
    return (PVOID)((ULONG_PTR)val ^ (ULONG_PTR)g_StateKey);
}

} // namespace kc
