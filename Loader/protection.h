#pragma once
/*
 * protection.h — Anti-RE, Anti-Debug, Anti-DLL-Injection protections
 *
 * Layered defense:
 *   1. Anti-debugger detection (multiple methods)
 *   2. Anti-DLL injection (monitor loaded modules)
 *   3. PE header erasure (anti-dump)
 *   4. Timing-based anti-debug
 *   5. Thread-hiding from debugger
 *   6. Integrity check (detect patching)
 */

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <cstdio>
#include <string>
#include <vector>
#include <thread>
#include <atomic>

#include "skStr.h"

#pragma comment(lib, "ntdll.lib")

namespace protection {

// ── Forward declarations for NT internals ───────────────────────
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
    HANDLE, UINT, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    UINT, PVOID, ULONG, PULONG);

static std::atomic<bool> g_protectionRunning{ false };
static std::atomic<uint32_t> g_moduleSnapshot{ 0 };
static std::atomic<uint32_t> g_textSectionCRC{ 0 };

// ── CRC32 for integrity checks ──────────────────────────────────
static uint32_t crc32_compute(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
    return ~crc;
}

// ── 1. Anti-Debugger Detection ──────────────────────────────────

static bool CheckIsDebuggerPresent() {
    return IsDebuggerPresent() != FALSE;
}

static bool CheckRemoteDebugger() {
    BOOL debugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
    return debugged != FALSE;
}

static bool CheckNtQueryDebugPort() {
    auto NtQIP = (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQIP) return false;

    ULONG_PTR debugPort = 0;
    NTSTATUS status = NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)7,
                            &debugPort, sizeof(debugPort), nullptr);
    return NT_SUCCESS(status) && debugPort != 0;
}

static bool CheckNtQueryDebugFlags() {
    auto NtQIP = (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQIP) return false;

    ULONG debugFlags = 0;
    NTSTATUS status = NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)0x1F,
                            &debugFlags, sizeof(debugFlags), nullptr);
    return NT_SUCCESS(status) && debugFlags == 0;
}

static bool CheckNtQueryDebugObject() {
    auto NtQIP = (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQIP) return false;

    HANDLE debugObj = nullptr;
    NTSTATUS status = NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)0x1E,
                            &debugObj, sizeof(debugObj), nullptr);
    return NT_SUCCESS(status) && debugObj != nullptr;
}

static bool CheckPEB() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    return pPeb->BeingDebugged != 0;
}

static bool CheckNtGlobalFlag() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    ULONG ntGlobalFlag = *(ULONG*)((BYTE*)pPeb + 0xBC);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    ULONG ntGlobalFlag = *(ULONG*)((BYTE*)pPeb + 0x68);
#endif
    return (ntGlobalFlag & 0x70) != 0;
}

static bool CheckTimingRDTSC() {
    ULONGLONG t1 = __rdtsc();
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    ULONGLONG t2 = __rdtsc();
    return (t2 - t1) > 10000000;
}

static bool CheckHardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
    }
    return false;
}

static bool IsDebuggerDetected() {
    return CheckIsDebuggerPresent() ||
           CheckRemoteDebugger() ||
           CheckNtQueryDebugPort() ||
           CheckNtQueryDebugFlags() ||
           CheckNtQueryDebugObject() ||
           CheckPEB() ||
           CheckNtGlobalFlag() ||
           CheckHardwareBreakpoints();
}

// ── 2. Anti-DLL Injection ───────────────────────────────────────

static uint32_t CountLoadedModules() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);
    uint32_t count = 0;

    if (Module32FirstW(hSnap, &me)) {
        do { count++; } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    return count;
}

static bool CheckSuspiciousModules() {
    const wchar_t* suspicious[] = {
        L"x64dbg.dll", L"x32dbg.dll", L"ScyllaHide",
        L"SharpOD", L"TitanHide", L"HyperHide",
        L"cheat engine", L"CheatEngine", L"ce-",
        L"ida", L"olly", L"dnSpy",
        L"MegaDumper", L"Scylla", L"pe-sieve",
        L"vmware", L"vbox"
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);
    bool found = false;

    if (Module32FirstW(hSnap, &me)) {
        do {
            std::wstring modName(me.szModule);
            for (auto& c : modName) c = towlower(c);

            for (auto& s : suspicious) {
                std::wstring sLower(s);
                for (auto& c : sLower) c = towlower(c);
                if (modName.find(sLower) != std::wstring::npos) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    return found;
}

// ── 3. Hide Thread from Debugger ────────────────────────────────
static void HideThreadFromDebugger() {
    auto NtSIT = (pNtSetInformationThread)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
    if (NtSIT) {
        NtSIT(GetCurrentThread(), 0x11, nullptr, 0);
    }
}

// ── 4. Erase PE Header from Memory (anti-dump) ─────────────────
static void ErasePEHeader() {
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod) return;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);

    DWORD headerSize = pNt->OptionalHeader.SizeOfHeaders;
    DWORD oldProtect = 0;

    if (VirtualProtect(hMod, headerSize, PAGE_READWRITE, &oldProtect)) {
        SecureZeroMemory(hMod, headerSize);
        VirtualProtect(hMod, headerSize, oldProtect, &oldProtect);
    }
}

// ── 5. .text Section Integrity Check ────────────────────────────
static uint32_t ComputeTextSectionCRC() {
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod) return 0;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSec[i].Name, ".text", 5) == 0) {
            uint8_t* start = (uint8_t*)hMod + pSec[i].VirtualAddress;
            uint32_t size = pSec[i].Misc.VirtualSize;
            return crc32_compute(start, size);
        }
    }
    return 0;
}

// ── 6. Check for Suspicious Windows ─────────────────────────────
static bool CheckDebuggerWindows() {
    const char* debuggerClasses[] = {
        "OLLYDBG", "ID", "WinDbgFrameClass", "idaabortiondialog",
        "zabortiondialog", "Rock_Debugger", "ObsidianGUI"
    };
    const char* debuggerTitles[] = {
        "x64dbg", "x32dbg", "IDA", "Cheat Engine",
        "Process Hacker", "Process Monitor", "OllyDbg",
        "Scylla", "MegaDumper", "PE-bear", "Ghidra"
    };

    for (auto& cls : debuggerClasses) {
        if (FindWindowA(cls, nullptr)) return true;
    }
    for (auto& title : debuggerTitles) {
        if (FindWindowA(nullptr, title)) return true;
    }
    return false;
}

// ── Background Protection Thread ────────────────────────────────
static void ProtectionThread() {
    HideThreadFromDebugger();

    while (g_protectionRunning.load()) {
        if (IsDebuggerDetected()) {
            *((volatile int*)0) = 0;
        }

        if (CheckTimingRDTSC()) {
            *((volatile int*)0) = 0;
        }

        uint32_t currentModules = CountLoadedModules();
        uint32_t baseline = g_moduleSnapshot.load();
        if (baseline > 0 && currentModules > baseline + 20) {
            *((volatile int*)0) = 0;
        }

        if (CheckSuspiciousModules()) {
            *((volatile int*)0) = 0;
        }

        if (CheckDebuggerWindows()) {
            *((volatile int*)0) = 0;
        }

        // CRC check disabled — too many false positives from runtime DLL loading
        // (KeyAuth, COM/OLE, intel driver service). Module count + anti-debug is sufficient.

        Sleep(3000 + (GetTickCount() % 2000));
    }
}

// ── Public API ──────────────────────────────────────────────────

inline bool InitProtection() {
    HideThreadFromDebugger();

    if (IsDebuggerDetected()) {
        printf(skCrypt("\n [!] Environment check failed.\n"));
        return false;
    }

    if (CheckDebuggerWindows()) {
        return false;
    }

    if (CheckSuspiciousModules()) {
        printf(skCrypt("\n [!] Suspicious software detected.\n"));
        return false;
    }

    g_moduleSnapshot.store(CountLoadedModules());
    // NOTE: Do NOT compute .text CRC here — KeyAuth networking DLLs
    // haven't loaded yet, and PostAuthHarden will erase the PE header.
    // CRC baseline is set in PostAuthHarden() after everything stabilizes.

    // Watchdog thread disabled — one-time checks above are sufficient.
    // Background thread caused false positives from runtime DLL loading
    // (COM, intel driver service, WinINet, etc.)
    g_protectionRunning.store(false);

    return true;
}

inline void PostAuthHarden() {
    ErasePEHeader();
    // Re-snapshot after KeyAuth loaded networking DLLs (WinHTTP, libsodium, etc.)
    g_moduleSnapshot.store(CountLoadedModules());
    // Now compute .text CRC baseline — PE header is erased, all DLLs loaded
    g_textSectionCRC.store(ComputeTextSectionCRC());
}

inline void RefreshBaseline() {
    g_moduleSnapshot.store(CountLoadedModules());
    g_textSectionCRC.store(ComputeTextSectionCRC());
}

inline void StopProtection() {
    g_protectionRunning.store(false);
}

} // namespace protection
