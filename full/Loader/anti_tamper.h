#pragma once
/*
 * anti_tamper.h — Comprehensive anti-tamper, anti-attach, anti-inject
 *
 * Layers:
 *   1. TLS callback anti-debug (runs BEFORE main)
 *   2. Parent process validation
 *   3. Anti-debugger attachment (post-launch)
 *   4. DLL load notification monitoring
 *   5. Foreign thread detection
 *   6. Kernel debugger detection
 *   7. Exception-based traps (INT 2D)
 *   8. WinHTTP hook detection
 *   9. Auth response integrity
 *  10. Critical code integrity monitoring
 */

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <cstdint>
#include <cstdio>
#include <atomic>
#include <vector>
#include <string>

#pragma comment(lib, "ntdll.lib")

#ifndef DEBUG_ALL_ACCESS
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1F)
#endif

namespace antitamper {

static std::atomic<bool> g_Initialized{ false };
static std::atomic<DWORD> g_MainThreadId{ 0 };
static std::vector<DWORD> g_KnownThreads;
static CRITICAL_SECTION g_ThreadLock;

// ══════════════════════════════════════════════════════════
//  1. TLS CALLBACK — Runs BEFORE main(), catches early debug
// ══════════════════════════════════════════════════════════

static void SilentExit() {
    TerminateProcess(GetCurrentProcess(), 0xDEAD);
}

static void NTAPI TlsAntiDebug(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason != DLL_PROCESS_ATTACH) return;

    // PEB.BeingDebugged
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    if (pPeb->BeingDebugged) SilentExit();

    // NtGlobalFlag
#ifdef _WIN64
    ULONG ntg = *(ULONG*)((BYTE*)pPeb + 0xBC);
#else
    ULONG ntg = *(ULONG*)((BYTE*)pPeb + 0x68);
#endif
    if (ntg & 0x70) SilentExit();

    // Heap flags — ONLY for NT heap (not Segment Heap which is default on Win10 2004+)
    // Segment Heap has signature 0xFFEEFFEE at offset 0x00; NT Heap has 0xFFEEFFEE at offset 0x00 too
    // but the layout differs. We check the heap encoding cookie to detect Segment Heap.
#ifdef _WIN64
    void* heap = *(void**)((BYTE*)pPeb + 0x30);
    // Only check ForceFlags if this looks like an NT heap (Segment Heap starts with different sig)
    ULONG heapSig = *(ULONG*)((BYTE*)heap + 0x00);
    if (heapSig != 0xFFEEFFEE) {
        // Likely Segment Heap — skip raw offset check, use API instead
        if (IsDebuggerPresent()) SilentExit();
    } else {
        ULONG force = *(ULONG*)((BYTE*)heap + 0x74);
        if (force != 0) SilentExit();
    }
#else
    void* heap = *(void**)((BYTE*)pPeb + 0x18);
    ULONG force = *(ULONG*)((BYTE*)heap + 0x44);
    if (force != 0) SilentExit();
#endif
}

// ══════════════════════════════════════════════════════════
//  2. PARENT PROCESS VALIDATION
// ══════════════════════════════════════════════════════════

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

static bool ValidateParentProcess() {
    auto NtQIP = (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQIP) return true; // can't check, don't block

    // Get parent PID
    struct PROCESS_BASIC_INFO {
        PVOID Reserved1;
        PPEB PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } pbi = {};

    NTSTATUS st = NtQIP(GetCurrentProcess(), ProcessBasicInformation,
                        &pbi, sizeof(pbi), nullptr);
    if (!NT_SUCCESS(st)) return true;

    DWORD parentPid = (DWORD)pbi.InheritedFromUniqueProcessId;
    if (parentPid == 0) return true;

    // Open parent and get its name
    HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    if (!hParent) return true; // parent already exited, OK

    wchar_t parentPath[MAX_PATH] = {};
    DWORD pathSize = MAX_PATH;

    typedef BOOL(WINAPI* pQueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
    auto QueryName = (pQueryFullProcessImageNameW)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "QueryFullProcessImageNameW");

    bool valid = true;
    if (QueryName && QueryName(hParent, 0, parentPath, &pathSize)) {
        // Extract filename
        wchar_t* fileName = parentPath;
        for (wchar_t* p = parentPath; *p; p++)
            if (*p == L'\\' || *p == L'/') fileName = p + 1;

        // Convert to lowercase
        for (wchar_t* p = fileName; *p; p++)
            *p = towlower(*p);

        // Blocked parent processes (debuggers, analysis tools)
        const wchar_t* blocked[] = {
            L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe",
            L"ida.exe", L"ida64.exe", L"idaq.exe", L"idaq64.exe",
            L"windbg.exe", L"windbgx.exe", L"kd.exe", L"cdb.exe",
            L"devenv.exe", L"ghidra.exe", L"binaryninja.exe",
            L"dnspy.exe", L"dotpeek.exe",
            L"cheatengine-x86_64.exe", L"cheatengine.exe",
            L"processhacker.exe", L"procexp.exe", L"procexp64.exe",
            L"httpdebugger.exe", L"fiddler.exe", L"charles.exe",
            L"python.exe", L"pythonw.exe", L"java.exe", L"javaw.exe",
            L"powershell.exe", L"powershell_ise.exe", L"pwsh.exe",
        };

        for (auto& b : blocked) {
            if (_wcsicmp(fileName, b) == 0) { valid = false; break; }
        }
    }

    CloseHandle(hParent);
    return valid;
}

// ══════════════════════════════════════════════════════════
//  3. ANTI-DEBUGGER ATTACHMENT (post-launch)
// ══════════════════════════════════════════════════════════

// Self-debug trick: attach a debug object to ourselves so no external
// debugger can attach. Uses NtCreateDebugObject + NtSetInformationProcess.
static HANDLE g_SelfDebugObject = nullptr;

static void PreventDebuggerAttach() {
    typedef NTSTATUS(NTAPI* pNtCreateDebugObject)(PHANDLE, ACCESS_MASK, PVOID, ULONG);
    typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);

    auto NtCreateDebugObject = (pNtCreateDebugObject)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtCreateDebugObject");
    auto NtSetInfoProc = (pNtSetInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");

    if (!NtCreateDebugObject || !NtSetInfoProc) return;

    // Create debug object
    HANDLE debugObj = nullptr;
    NTSTATUS st = NtCreateDebugObject(&debugObj, DEBUG_ALL_ACCESS, nullptr, 1);
    if (!NT_SUCCESS(st) || !debugObj) return;

    // Attach it to ourselves (ProcessDebugObjectHandle = 30)
    st = NtSetInfoProc(GetCurrentProcess(), 30, &debugObj, sizeof(debugObj));
    if (NT_SUCCESS(st)) {
        g_SelfDebugObject = debugObj;
    } else {
        CloseHandle(debugObj);
    }
}

// ══════════════════════════════════════════════════════════
//  4. DLL LOAD NOTIFICATION — Detect injected DLLs
// ══════════════════════════════════════════════════════════

typedef struct _LDR_DLL_NOTIFICATION_DATA {
    ULONG Flags;
    const UNICODE_STRING* FullDllName;
    const UNICODE_STRING* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK* PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG Reason, const LDR_DLL_NOTIFICATION_DATA* Data, PVOID Context);

typedef NTSTATUS(NTAPI* pLdrRegisterDllNotification)(
    ULONG Flags, PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID Context, PVOID* Cookie);

static PVOID g_DllNotifCookie = nullptr;
static std::atomic<bool> g_DllMonitorActive{ false };

// Allowlist of DLLs that are expected to load
static bool IsAllowedDll(const wchar_t* name) {
    if (!name) return true;

    // Convert to lowercase for comparison
    wchar_t lower[MAX_PATH] = {};
    for (int i = 0; i < MAX_PATH - 1 && name[i]; i++)
        lower[i] = towlower(name[i]);

    // System DLLs that legitimately load during WinHTTP, crypto, etc.
    const wchar_t* allowed[] = {
        L"kernel32", L"ntdll", L"kernelbase", L"user32", L"gdi32",
        L"advapi32", L"shell32", L"ole32", L"oleaut32", L"combase",
        L"msvcrt", L"ucrtbase", L"vcruntime", L"msvcp",
        L"winhttp", L"wininet", L"ws2_32", L"sechost", L"crypt32",
        L"bcrypt", L"ncrypt", L"schannel", L"sspicli", L"mswsock",
        L"dnsapi", L"iphlpapi", L"nsi", L"wldap32", L"normaliz",
        L"secur32", L"rpcrt4", L"msasn1", L"wintrust", L"rsaenh",
        L"cryptsp", L"cryptbase", L"dpapi", L"bcryptprimitives",
        L"cfgmgr32", L"setupapi", L"devobj", L"wtsapi32", L"version",
        L"profapi", L"powrprof", L"shlwapi", L"imm32", L"msctf",
        L"clbcatq", L"comctl32", L"uxtheme", L"dwmapi",
        L"winnsi", L"fwpuclnt", L"rasadhlp", L"ondemandconnroute",
        L"webio", L"winrnr", L"napinsp", L"pnrpnsp", L"nlaapi",
        L"wshbth", L"dbghelp", L"dbgcore",
        L"apphelp", L"shcore", L"propsys", L"psapi",
    };

    for (auto& a : allowed) {
        if (wcsstr(lower, a)) return true;
    }

    // Allow anything from System32 or SysWOW64
    if (wcsstr(lower, L"system32") || wcsstr(lower, L"syswow64"))
        return true;

    return false;
}

static VOID CALLBACK DllLoadCallback(
    ULONG Reason, const LDR_DLL_NOTIFICATION_DATA* Data, PVOID Context)
{
    if (!g_DllMonitorActive.load()) return;
    if (Reason != 1) return; // 1 = LDR_DLL_NOTIFICATION_REASON_LOADED

    const wchar_t* dllName = Data->FullDllName ? Data->FullDllName->Buffer : nullptr;
    if (!dllName) dllName = Data->BaseDllName ? Data->BaseDllName->Buffer : nullptr;

    if (!IsAllowedDll(dllName)) {
        // Suspicious DLL injected — terminate immediately
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
    }
}

static void StartDllMonitoring() {
    auto LdrRegister = (pLdrRegisterDllNotification)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "LdrRegisterDllNotification");
    if (!LdrRegister) return;

    LdrRegister(0, DllLoadCallback, nullptr, &g_DllNotifCookie);
    g_DllMonitorActive.store(true);
}

// ══════════════════════════════════════════════════════════
//  5. FOREIGN THREAD DETECTION
// ══════════════════════════════════════════════════════════

static void RecordThread(DWORD tid) {
    EnterCriticalSection(&g_ThreadLock);
    g_KnownThreads.push_back(tid);
    LeaveCriticalSection(&g_ThreadLock);
}

static bool IsKnownThread(DWORD tid) {
    EnterCriticalSection(&g_ThreadLock);
    for (auto& t : g_KnownThreads) {
        if (t == tid) { LeaveCriticalSection(&g_ThreadLock); return true; }
    }
    LeaveCriticalSection(&g_ThreadLock);
    return false;
}

static bool DetectForeignThreads() {
    DWORD myPid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te = { sizeof(te) };
    int foreignCount = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != myPid) continue;
            if (!IsKnownThread(te.th32ThreadID)) {
                foreignCount++;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    // Windows creates many legitimate threads: thread pool workers (4-8),
    // WinHTTP async callbacks, COM/RPC threads, timer threads, etc.
    // Threshold must be generous to avoid false positives.
    return foreignCount > 20;
}

// ══════════════════════════════════════════════════════════
//  6. KERNEL DEBUGGER DETECTION
// ══════════════════════════════════════════════════════════

static bool DetectKernelDebugger() {
    // NOTE: SharedUserData->KdDebuggerEnabled is NOT used because Hyper-V
    // (enabled by default on Win11, common on Win10 with WSL2/Docker)
    // sets it to true even without an actual kernel debugger.

    // NtQuerySystemInformation - SystemKernelDebuggerInformation (35)
    // This properly distinguishes Hyper-V from real kd via DebuggerNotPresent flag.
    typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
    auto NtQSI = (pNtQuerySystemInformation)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (NtQSI) {
        struct { BOOLEAN DebuggerEnabled; BOOLEAN DebuggerNotPresent; } kdi = {};
        NTSTATUS st = NtQSI(35, &kdi, sizeof(kdi), nullptr);
        if (NT_SUCCESS(st) && kdi.DebuggerEnabled && !kdi.DebuggerNotPresent)
            return true;
    }

    return false;
}

// ══════════════════════════════════════════════════════════
//  7. EXCEPTION-BASED TRAPS
// ══════════════════════════════════════════════════════════

// INT 2D: debuggers consume this interrupt differently than normal execution
static bool TrapInt2D() {
    __try {
        __debugbreak(); // INT 3
        // If debugger is present and handles INT 3, we won't reach the except
        return true; // should not reach here normally
    }
    __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ?
              EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return false; // normal execution — exception was raised and caught
    }
}

// OutputDebugString: DISABLED — unreliable on modern Windows (Win10+).
// GetLastError() behavior after OutputDebugStringA changed and produces
// false positives regardless of debugger presence.
static bool TrapOutputDebugString() {
    return false; // disabled — too many false positives
}

// ══════════════════════════════════════════════════════════
//  8. WINHTTP INTEGRITY — Detect hooks on auth functions
// ══════════════════════════════════════════════════════════

static bool CheckWinHttpIntegrity() {
    HMODULE hWinHttp = GetModuleHandleA("winhttp.dll");
    if (!hWinHttp) return true; // not loaded yet

    // Check critical WinHTTP functions for inline hooks
    const char* funcs[] = {
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
        "WinHttpSendRequest", "WinHttpReceiveResponse",
        "WinHttpReadData", "WinHttpCloseHandle",
    };

    auto* dos = (IMAGE_DOS_HEADER*)hWinHttp;
    auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)hWinHttp + dos->e_lfanew);
    BYTE* modStart = (BYTE*)hWinHttp;
    BYTE* modEnd = modStart + nt->OptionalHeader.SizeOfImage;

    for (auto& fn : funcs) {
        BYTE* addr = (BYTE*)GetProcAddress(hWinHttp, fn);
        if (!addr) continue;

        // Check first bytes for jmp/call hooks
        if (addr[0] == 0xE9 || addr[0] == 0xEB ||
            (addr[0] == 0xFF && addr[1] == 0x25)) {
            return false; // hooked!
        }

        // Verify function is inside the module
        if (addr < modStart || addr >= modEnd)
            return false; // redirected outside module
    }

    return true;
}

// ══════════════════════════════════════════════════════════
//  9. CRITICAL CODE REGION INTEGRITY
// ══════════════════════════════════════════════════════════

static uint32_t g_AuthFuncCRC = 0;
static BYTE* g_AuthFuncAddr = nullptr;
static size_t g_AuthFuncSize = 0;

static uint32_t Crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
    return ~crc;
}

// Call after auth function is resolved to snapshot its code
static void SnapshotAuthFunction(void* funcAddr, size_t size) {
    g_AuthFuncAddr = (BYTE*)funcAddr;
    g_AuthFuncSize = size;
    g_AuthFuncCRC = Crc32((uint8_t*)funcAddr, size);
}

static bool VerifyAuthIntegrity() {
    if (!g_AuthFuncAddr || !g_AuthFuncSize || !g_AuthFuncCRC) return true;
    return Crc32((uint8_t*)g_AuthFuncAddr, g_AuthFuncSize) == g_AuthFuncCRC;
}

// ══════════════════════════════════════════════════════════
// 10. PROCESS MITIGATION POLICIES — OS-level hardening
// ══════════════════════════════════════════════════════════

static void ApplyProcessMitigations() {
    // Prevent non-Microsoft DLLs from being loaded (blocks most injectors)
    typedef BOOL(WINAPI* pSetProcessMitigationPolicy)(DWORD, PVOID, SIZE_T);
    auto SetPolicy = (pSetProcessMitigationPolicy)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "SetProcessMitigationPolicy");
    if (!SetPolicy) return;

    // Block non-Microsoft signed DLLs (ProcessSignaturePolicy = 8)
    struct { DWORD MicrosoftSignedOnly : 1; DWORD StoreSignedOnly : 1; DWORD MitigationOptIn : 1; } sigPolicy = {};
    sigPolicy.MicrosoftSignedOnly = 1;
    sigPolicy.MitigationOptIn = 1;
    SetPolicy(8, &sigPolicy, sizeof(sigPolicy));

    // Block dynamic code generation (ProcessDynamicCodePolicy = 2)
    // NOTE: This would break our syscall stubs, so we DON'T enable it

    // Block Win32k system calls — not needed for console app (ProcessSystemCallDisablePolicy = 3)
    struct { DWORD DisallowWin32kSystemCalls : 1; } sysPolicy = {};
    sysPolicy.DisallowWin32kSystemCalls = 1;
    // Don't enable — may break CreateToolhelp32Snapshot

    // Disable extension points (ProcessExtensionPointDisablePolicy = 6)
    struct { DWORD DisableExtensionPoints : 1; } extPolicy = {};
    extPolicy.DisableExtensionPoints = 1;
    SetPolicy(6, &extPolicy, sizeof(extPolicy));

    // Control Flow Guard — compiler must support, just ensure it's on
    // ProcessControlFlowGuardPolicy = 7 — handled by compiler /guard:cf
}

// ══════════════════════════════════════════════════════════
// 11. TIMER RESOLUTION DETECTION
//     Debuggers often change timer resolution for stepping
// ══════════════════════════════════════════════════════════

static bool CheckTimerResolution() {
    typedef NTSTATUS(NTAPI* pNtQueryTimerResolution)(PULONG, PULONG, PULONG);
    auto NtQTR = (pNtQueryTimerResolution)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryTimerResolution");
    if (!NtQTR) return false;

    ULONG minRes, maxRes, curRes;
    if (NT_SUCCESS(NtQTR(&minRes, &maxRes, &curRes))) {
        // Normal resolution is ~156250 (15.625ms). Debuggers set to ~5000 (0.5ms).
        // Gaming mice, Chrome, multimedia apps commonly set to ~10000 (1ms),
        // so only flag resolutions below 2000 (0.2ms) which is debugger-specific.
        if (curRes < 2000) return true;
    }
    return false;
}

// ══════════════════════════════════════════════════════════
//  PUBLIC API
// ══════════════════════════════════════════════════════════

// Call at very start of main() — basic init
inline void Init() {
    InitializeCriticalSection(&g_ThreadLock);
    g_MainThreadId.store(GetCurrentThreadId());
    RecordThread(GetCurrentThreadId());
    g_Initialized.store(true);
}

// Record threads we create ourselves
inline void RegisterThread(DWORD tid) {
    RecordThread(tid);
}

// Full pre-auth environment scan
inline bool FullEnvironmentCheck() {
    // Parent process check
    if (!ValidateParentProcess()) return false;

    // Kernel debugger
    if (DetectKernelDebugger()) return false;

    // Exception traps (don't fail on these alone — combine with other checks)
    int suspicionScore = 0;
    if (TrapOutputDebugString()) suspicionScore++;
    if (CheckTimerResolution()) suspicionScore++;

    // Only fail if multiple weak indicators fire together
    if (suspicionScore >= 2) return false;

    return true;
}

// Call after auth — lock down the process
inline void LockdownProcess() {
    // Prevent debugger attachment
    PreventDebuggerAttach();

    // Start DLL load monitoring
    StartDllMonitoring();

    // Apply OS-level mitigations
    ApplyProcessMitigations();
}

// Periodic check (called from watchdog)
inline bool PeriodicCheck() {
    // Foreign thread detection
    if (DetectForeignThreads()) {
        printf("[ANTITAMPER] FAIL: ForeignThreads\n"); fflush(stdout);
        return false;
    }

    // WinHTTP integrity
    if (!CheckWinHttpIntegrity()) {
        printf("[ANTITAMPER] FAIL: WinHttpIntegrity\n"); fflush(stdout);
        return false;
    }

    // Auth function integrity
    if (!VerifyAuthIntegrity()) {
        printf("[ANTITAMPER] FAIL: AuthIntegrity\n"); fflush(stdout);
        return false;
    }

    // Kernel debugger (can be attached at any time)
    if (DetectKernelDebugger()) {
        printf("[ANTITAMPER] FAIL: KernelDebugger\n"); fflush(stdout);
        return false;
    }

    return true;
}

} // namespace antitamper

// ══════════════════════════════════════════════════════════
//  TLS CALLBACK REGISTRATION
//  This runs BEFORE main() — catches early debugger attach
// ══════════════════════════════════════════════════════════
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLB")
extern "C" const PIMAGE_TLS_CALLBACK tls_callback_func = antitamper::TlsAntiDebug;
#pragma const_seg()
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback_func")
#pragma data_seg(".CRT$XLB")
extern "C" PIMAGE_TLS_CALLBACK tls_callback_func = antitamper::TlsAntiDebug;
#pragma data_seg()
#endif
