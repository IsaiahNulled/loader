#pragma once
/*
 * loader_guard.h — Advanced loader hardening
 *
 * Layers: API hashing, direct syscalls, enhanced anti-debug,
 * anti-VM/sandbox, IAT/ntdll hook detection, analysis tool detection,
 * hardened watchdog with controlled exit.
 */

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <cstdint>
#include <cstring>
#include <thread>
#include <atomic>

// Forward declarations — defined in anti_tamper.h
namespace antitamper { inline bool PeriodicCheck(); inline void RegisterThread(DWORD tid); }

namespace guard {

// ══════════════════════════════════════════════════════════
//  1. COMPILE-TIME API HASHING + PEB-BASED RESOLUTION
// ══════════════════════════════════════════════════════════

constexpr uint32_t FNV_OFF = 0x811C9DC5;
constexpr uint32_t FNV_PR  = 0x01000193;

constexpr uint32_t fnv1a_ct(const char* s, uint32_t h = FNV_OFF) {
    return (*s == 0) ? h : fnv1a_ct(s + 1, (h ^ (uint8_t)*s) * FNV_PR);
}
static uint32_t fnv1a_ci(const wchar_t* s) {
    uint32_t h = FNV_OFF;
    while (*s) { wchar_t c = (*s >= L'A' && *s <= L'Z') ? *s + 32 : *s; s++;
        h = (h ^ (uint8_t)c) * FNV_PR; }
    return h;
}
static uint32_t fnv1a_rt(const char* s) {
    uint32_t h = FNV_OFF;
    while (*s) { h = (h ^ (uint8_t)*s++) * FNV_PR; }
    return h;
}

static void* ResolveByHash(uint32_t modHash, uint32_t funcHash) {
#ifdef _WIN64
    auto* pPeb = (PEB*)__readgsqword(0x60);
#else
    auto* pPeb = (PEB*)__readfsdword(0x30);
#endif
    auto* head = &pPeb->Ldr->InMemoryOrderModuleList;
    for (auto* e = head->Flink; e != head; e = e->Flink) {
        auto* mod = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!mod->DllBase) continue;
        const wchar_t* fn = mod->FullDllName.Buffer;
        for (const wchar_t* p = fn; *p; p++)
            if (*p == L'\\' || *p == L'/') fn = p + 1;
        if (fnv1a_ci(fn) != modHash) continue;

        auto* dos = (IMAGE_DOS_HEADER*)mod->DllBase;
        auto* nt  = (IMAGE_NT_HEADERS*)((BYTE*)mod->DllBase + dos->e_lfanew);
        auto& ed  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!ed.VirtualAddress) continue;
        auto* exp   = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)mod->DllBase + ed.VirtualAddress);
        auto* names = (DWORD*)((BYTE*)mod->DllBase + exp->AddressOfNames);
        auto* ords  = (WORD*) ((BYTE*)mod->DllBase + exp->AddressOfNameOrdinals);
        auto* funcs = (DWORD*)((BYTE*)mod->DllBase + exp->AddressOfFunctions);
        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            if (fnv1a_rt((const char*)((BYTE*)mod->DllBase + names[i])) == funcHash)
                return (void*)((BYTE*)mod->DllBase + funcs[ords[i]]);
        }
    }
    return nullptr;
}

#define HASH_API(mod, func) \
    ((decltype(&func))guard::ResolveByHash(guard::fnv1a_ct(mod), guard::fnv1a_ct(#func)))


// ══════════════════════════════════════════════════════════
//  2. DIRECT NT SYSCALL STUBS (bypass usermode hooks)
// ══════════════════════════════════════════════════════════

static HMODULE GetNtdllBase() {
#ifdef _WIN64
    auto* pPeb = (PEB*)__readgsqword(0x60);
#else
    auto* pPeb = (PEB*)__readfsdword(0x30);
#endif
    auto* head = &pPeb->Ldr->InMemoryOrderModuleList;
    auto* second = head->Flink->Flink; // ntdll is always 2nd
    auto* mod = CONTAINING_RECORD(second, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return (HMODULE)mod->DllBase;
}

static DWORD ReadSyscallNumber(HMODULE ntdll, const char* name) {
    auto* dos  = (IMAGE_DOS_HEADER*)ntdll;
    auto* nt   = (IMAGE_NT_HEADERS*)((BYTE*)ntdll + dos->e_lfanew);
    auto& ed   = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto* exp  = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntdll + ed.VirtualAddress);
    auto* ns   = (DWORD*)((BYTE*)ntdll + exp->AddressOfNames);
    auto* os   = (WORD*) ((BYTE*)ntdll + exp->AddressOfNameOrdinals);
    auto* fs   = (DWORD*)((BYTE*)ntdll + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (strcmp((const char*)((BYTE*)ntdll + ns[i]), name) != 0) continue;
        BYTE* fn = (BYTE*)ntdll + fs[os[i]];
        // Standard: 4C 8B D1 B8 XX XX XX XX
        if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8)
            return *(DWORD*)(fn + 4);
        // If hooked, scan for mov eax + syscall pattern
        for (int j = 0; j < 64; j++)
            if (fn[j] == 0xB8 && j + 6 < 64 && fn[j+5] == 0x0F && fn[j+6] == 0x05)
                return *(DWORD*)(fn + j + 1);
        break;
    }
    return 0;
}

static void* BuildSyscallStub(DWORD number) {
    void* mem = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return nullptr;
    BYTE code[] = {
        0x4C, 0x8B, 0xD1,                 // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, <number>
        0x0F, 0x05,                         // syscall
        0xC3                                // ret
    };
    *(DWORD*)(code + 4) = number;
    memcpy(mem, code, sizeof(code));
    DWORD old;
    VirtualProtect(mem, 64, PAGE_EXECUTE_READ, &old);
    return mem;
}

using NtQIP_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NtQIP_t g_DirectNtQIP = nullptr;

static bool InitDirectSyscalls() {
    HMODULE ntdll = GetNtdllBase();
    if (!ntdll) return false;
    DWORD num = ReadSyscallNumber(ntdll, "NtQueryInformationProcess");
    if (!num) return false;
    void* stub = BuildSyscallStub(num);
    if (!stub) return false;
    g_DirectNtQIP = (NtQIP_t)stub;
    return true;
}


// ══════════════════════════════════════════════════════════
//  3. ENHANCED ANTI-DEBUG (supplements protection.h)
// ══════════════════════════════════════════════════════════

// Heap flags — debugger enables page-heap validation
// NOTE: Windows 10 2004+ uses Segment Heap by default, which has a different
// internal layout. Raw offset checks only work on NT Heap.
static bool CheckHeapFlags() {
#ifdef _WIN64
    auto* pPeb  = (PPEB)__readgsqword(0x60);
    void* heap  = *(void**)((BYTE*)pPeb + 0x30);
    // Detect Segment Heap vs NT Heap by checking signature at offset 0
    ULONG heapSig = *(ULONG*)((BYTE*)heap + 0x00);
    if (heapSig != 0xFFEEFFEE) {
        // Segment Heap — can't use raw offsets, fall back to PEB.BeingDebugged
        return pPeb->BeingDebugged != 0;
    }
    ULONG flags = *(ULONG*)((BYTE*)heap + 0x70);
    ULONG force = *(ULONG*)((BYTE*)heap + 0x74);
#else
    auto* pPeb  = (PPEB)__readfsdword(0x30);
    void* heap  = *(void**)((BYTE*)pPeb + 0x18);
    ULONG flags = *(ULONG*)((BYTE*)heap + 0x40);
    ULONG force = *(ULONG*)((BYTE*)heap + 0x44);
#endif
    return (force != 0) || (flags & ~0x02u);
}

// CloseHandle trap — debugger raises EXCEPTION_INVALID_HANDLE
static bool CheckCloseHandleTrap() {
    __try {
        CloseHandle((HANDLE)(ULONG_PTR)0xDEADBEEF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
    return false;
}

// Debug port via direct syscall (unhookable)
static bool CheckDebugPortDirect() {
    if (!g_DirectNtQIP) return false;
    ULONG_PTR port = 0;
    NTSTATUS st = g_DirectNtQIP(GetCurrentProcess(), 7,
                                 &port, sizeof(port), nullptr);
    return NT_SUCCESS(st) && port != 0;
}

// Debug flags via direct syscall
static bool CheckDebugFlagsDirect() {
    if (!g_DirectNtQIP) return false;
    ULONG flags = 1;
    NTSTATUS st = g_DirectNtQIP(GetCurrentProcess(), 0x1F,
                                 &flags, sizeof(flags), nullptr);
    return NT_SUCCESS(st) && flags == 0;
}

// QPC timing — single-stepping blows up the delta
static bool CheckTimingQPC() {
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    volatile DWORD d = 0;
    for (int i = 0; i < 1000; i++) d += i * i;
    QueryPerformanceCounter(&t2);
    double ms = (double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart * 1000.0;
    return ms > 200.0;
}

static bool EnhancedAntiDebug() {
    return CheckDebugPortDirect()  ||
           CheckDebugFlagsDirect() ||
           CheckHeapFlags()        ||
           CheckCloseHandleTrap()  ||
           CheckTimingQPC();
}


// ══════════════════════════════════════════════════════════
//  4. ANTI-VM / ANTI-SANDBOX
// ══════════════════════════════════════════════════════════

static bool CpuidHypervisor() {
    int info[4] = {};
    __cpuid(info, 1);
    return (info[2] >> 31) & 1;
}

static bool CpuidHypervisorBrand() {
    int info[4] = {};
    __cpuid(info, 0x40000000);
    char brand[13] = {};
    memcpy(brand, &info[1], 12);
    const char* known[] = {
        "VMwareVMware", "VBoxVBoxVBox", "Microsoft Hv",
        "KVMKVMKVM\0\0\0", "XenVMMXenVMM",
    };
    for (auto& k : known)
        if (memcmp(brand, k, 12) == 0) return true;
    return false;
}

static bool VMRegistry() {
    HKEY hk;
    const wchar_t* keys[] = {
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        L"SYSTEM\\CurrentControlSet\\Services\\vmci",
        L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
    };
    for (auto& k : keys) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            RegCloseKey(hk);
            return true;
        }
    }
    return false;
}

static bool VMProcesses() {
    const wchar_t* procs[] = {
        L"vmtoolsd.exe", L"vmwaretray.exe", L"VBoxService.exe",
        L"VBoxTray.exe", L"qemu-ga.exe", L"vdagent.exe",
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = { sizeof(pe) };
    bool hit = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            for (auto& p : procs)
                if (_wcsicmp(pe.szExeFile, p) == 0) { hit = true; break; }
            if (hit) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return hit;
}

static bool SandboxHeuristics() {
    int cnt = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(snap, &pe))
            do { cnt++; } while (Process32NextW(snap, &pe));
        CloseHandle(snap);
    }
    if (cnt < 25) return true;
    if (GetTickCount64() < 5ULL * 60 * 1000) return true;
    MEMORYSTATUSEX mem = { sizeof(mem) };
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;
    if (GetSystemMetrics(SM_CXSCREEN) <= 800) return true;
    ULARGE_INTEGER total;
    if (GetDiskFreeSpaceExW(L"C:\\", nullptr, &total, nullptr))
        if (total.QuadPart < 60ULL * 1024 * 1024 * 1024) return true;
    return false;
}

// Score-based (avoids single false positive killing the app)
static int VMSandboxScore() {
    int s = 0;
    if (CpuidHypervisor())      s += 2;
    if (CpuidHypervisorBrand()) s += 5;
    if (VMRegistry())           s += 3;
    if (VMProcesses())          s += 4;
    if (SandboxHeuristics())    s += 3;
    return s;
}


// ══════════════════════════════════════════════════════════
//  5. IAT HOOK DETECTION + NTDLL INLINE HOOK DETECTION
// ══════════════════════════════════════════════════════════

// Count IAT entries that point outside their owning DLL
static int CountIATHooks() {
    HMODULE hMod = GetModuleHandleW(nullptr);
    auto* dos = (IMAGE_DOS_HEADER*)hMod;
    auto* nt  = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
    auto& id  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!id.VirtualAddress) return 0;

    int hooks = 0;
    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hMod + id.VirtualAddress);
    for (; desc->Name; desc++) {
        HMODULE hDll = GetModuleHandleA((const char*)((BYTE*)hMod + desc->Name));
        if (!hDll || !desc->OriginalFirstThunk) continue;

        auto* dDos = (IMAGE_DOS_HEADER*)hDll;
        auto* dNt  = (IMAGE_NT_HEADERS*)((BYTE*)hDll + dDos->e_lfanew);
        BYTE* lo = (BYTE*)hDll;
        BYTE* hi = lo + dNt->OptionalHeader.SizeOfImage;

        auto* ot = (IMAGE_THUNK_DATA*)((BYTE*)hMod + desc->OriginalFirstThunk);
        auto* ft = (IMAGE_THUNK_DATA*)((BYTE*)hMod + desc->FirstThunk);
        for (; ot->u1.AddressOfData; ot++, ft++) {
            BYTE* addr = (BYTE*)ft->u1.Function;
            if (addr < lo || addr >= hi) hooks++;
        }
    }
    return hooks;
}

// Detect jmp patches on critical ntdll Nt* functions
static bool DetectNtdllInlineHooks() {
    HMODULE ntdll = GetNtdllBase();
    if (!ntdll) return false;

    const char* critical[] = {
        "NtQueryInformationProcess", "NtQuerySystemInformation",
        "NtSetInformationThread",    "NtCreateThreadEx",
        "NtAllocateVirtualMemory",   "NtProtectVirtualMemory",
    };
    auto* dos = (IMAGE_DOS_HEADER*)ntdll;
    auto* nt  = (IMAGE_NT_HEADERS*)((BYTE*)ntdll + dos->e_lfanew);
    auto& ed  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntdll + ed.VirtualAddress);
    auto* names = (DWORD*)((BYTE*)ntdll + exp->AddressOfNames);
    auto* ords  = (WORD*) ((BYTE*)ntdll + exp->AddressOfNameOrdinals);
    auto* funcs = (DWORD*)((BYTE*)ntdll + exp->AddressOfFunctions);

    for (auto& fn : critical) {
        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            if (strcmp((const char*)((BYTE*)ntdll + names[i]), fn) != 0) continue;
            BYTE* code = (BYTE*)ntdll + funcs[ords[i]];
            if (code[0] == 0xE9 || code[0] == 0xE8 ||
                code[0] == 0xFF || code[0] == 0xEB)
                return true;
            break;
        }
    }
    return false;
}


// ══════════════════════════════════════════════════════════
//  6. ANALYSIS TOOL DETECTION (processes + drivers)
// ══════════════════════════════════════════════════════════

static bool DetectAnalysisProcesses() {
    const wchar_t* tools[] = {
        L"processhacker.exe",  L"procmon.exe",   L"procmon64.exe",
        L"procexp.exe",        L"procexp64.exe",
        L"wireshark.exe",      L"fiddler.exe",   L"charles.exe",
        L"dnspy.exe",          L"dotpeek.exe",   L"ilspy.exe",
        L"x64dbg.exe",        L"x32dbg.exe",    L"windbg.exe",
        L"ollydbg.exe",       L"ida.exe",       L"ida64.exe",
        L"ghidra.exe",        L"binaryninja.exe",
        L"cheatengine-x86_64.exe", L"cheatengine.exe",
        L"httpdebugger.exe",  L"httpdebuggerpro.exe",
        L"megadumper.exe",    L"scylla.exe",    L"scylla_x64.exe",
        L"pe-sieve64.exe",   L"hollows_hunter64.exe",
        L"apimonitor-x64.exe",L"apimonitor-x86.exe",
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = { sizeof(pe) };
    bool hit = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            for (auto& t : tools)
                if (_wcsicmp(pe.szExeFile, t) == 0) { hit = true; break; }
            if (hit) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return hit;
}

static bool DetectAnalysisDrivers() {
    const wchar_t* devs[] = {
        L"\\\\.\\PROCMON24",   L"\\\\.\\ICEEXT",
        L"\\\\.\\SICE",       L"\\\\.\\Syser",
        L"\\\\.\\SyserDbgMsg", L"\\\\.\\NTICE",
    };
    for (auto& d : devs) {
        HANDLE h = CreateFileW(d, 0, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
    }
    return false;
}


// ══════════════════════════════════════════════════════════
//  7. CONTROLLED EXIT + WATCHDOG THREAD
// ══════════════════════════════════════════════════════════

static std::atomic<bool> g_WatchdogRunning{ false };

// Wipe own image memory then terminate — makes dumps useless
static __declspec(noinline) void ControlledExit() {
    HMODULE hMod = GetModuleHandleW(nullptr);
    if (hMod) {
        auto* dos = (IMAGE_DOS_HEADER*)hMod;
        auto* nt  = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
        DWORD sz  = nt->OptionalHeader.SizeOfImage;
        DWORD old;
        if (VirtualProtect(hMod, sz, PAGE_READWRITE, &old))
            SecureZeroMemory(hMod, sz);
    }
    TerminateProcess(GetCurrentProcess(), 0);
}

static void WatchdogThread() {
    // Hide watchdog thread from debugger
    auto NtSIT = (NTSTATUS(NTAPI*)(HANDLE, UINT, PVOID, ULONG))
        ResolveByHash(fnv1a_ct("ntdll.dll"), fnv1a_ct("NtSetInformationThread"));
    if (NtSIT) NtSIT(GetCurrentThread(), 0x11, nullptr, 0);

    while (g_WatchdogRunning.load()) {
        // Debugger via direct syscall (unhookable)
        if (CheckDebugPortDirect()) {
            printf("[WATCHDOG] FAIL: DebugPort\n"); fflush(stdout);
            ControlledExit();
        }
        if (CheckDebugFlagsDirect()) {
            printf("[WATCHDOG] FAIL: DebugFlags\n"); fflush(stdout);
            ControlledExit();
        }

        // Hardware breakpoints
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx))
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                printf("[WATCHDOG] FAIL: HW breakpoints\n"); fflush(stdout);
                ControlledExit();
            }

        // Analysis tools
        if (DetectAnalysisProcesses()) {
            printf("[WATCHDOG] FAIL: AnalysisProcesses\n"); fflush(stdout);
            ControlledExit();
        }

        // Anti-tamper checks (foreign threads, WinHTTP hooks, code integrity, kernel debugger)
        if (!antitamper::PeriodicCheck()) {
            printf("[WATCHDOG] FAIL: PeriodicCheck\n"); fflush(stdout);
            ControlledExit();
        }

        // Randomized sleep to resist timing analysis
        Sleep(2000 + (GetTickCount() % 3000));
    }
}


// ══════════════════════════════════════════════════════════
//  PUBLIC API
// ══════════════════════════════════════════════════════════

// Call FIRST at startup — initializes syscall stubs
inline bool Init() {
    return InitDirectSyscalls();
}

// Call BEFORE authentication
inline bool PreAuthCheck() {
    if (EnhancedAntiDebug()) return false;
    if (VMSandboxScore() >= 8) return false;
    if (DetectAnalysisProcesses()) return false;
    if (DetectAnalysisDrivers()) return false;
    // ntdll inline hooks = AV/EDR, non-fatal (direct syscalls bypass them)
    return true;
}

// Call AFTER authentication — starts watchdog
inline void PostAuthHarden() {
    g_WatchdogRunning.store(true);
    std::thread([]() {
        antitamper::RegisterThread(GetCurrentThreadId());
        WatchdogThread();
    }).detach();
}

// Call on shutdown
inline void Stop() {
    g_WatchdogRunning.store(false);
}

} // namespace guard
