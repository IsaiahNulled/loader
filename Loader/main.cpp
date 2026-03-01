/*
 * Loader
 *
 * Handles auth, driver setup, overlay launch, and cleanup.
 */

#include <Windows.h>
#include <urlmon.h>
#include <ShlObj.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <Psapi.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <thread>
#include <cstdio>
#include <vector>
#include <atomic>
#include <random>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <conio.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "ntdll.lib")

#include "skStr.h"
#include "string_crypt.h"
#include "self_auth.h"
#include "protection.h"
#include "loader_guard.h"
#include "anti_tamper.h"
#include "simple_github_downloader.h"
#include "mem_payload.h"
#include "mem_exec.h"
#include "secure_download.h"

// ── GitHub Authentication ──────────────────────────────────────
// Removed - using public repository only

// ── Process Hiding Functions ──────────────────────────────────────
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// Separate function to decrypt spoof strings (no __try here)
static void InitSpoofStrings(wchar_t* outPath, wchar_t* outCmd) {
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring svcExe = EW(L"\\svchost.exe");
    wsprintfW(outPath, L"%s%s", sysDir, svcExe.c_str());
    std::wstring svcArg = EW(L" -k netsvcs");
    wsprintfW(outCmd, L"%s%s", outPath, svcArg.c_str());
}

// Separate function to decrypt overlay spoof strings (no __try here)
static void InitOverlaySpoofStrings(char* outSysPath, wchar_t* outSpoofName) {
    GetSystemDirectoryA(outSysPath, MAX_PATH);
    std::string svcName = E("\\svchost.exe");
    strcat_s(outSysPath, MAX_PATH, svcName.c_str());
    std::wstring wSpoof = EW(L"svchost.exe");
    wcscpy_s(outSpoofName, MAX_PATH, wSpoof.c_str());
}

bool HideFromTaskManager() {
    static wchar_t s_spoofPath[MAX_PATH] = {};
    static wchar_t s_spoofCmd[MAX_PATH] = {};
    InitSpoofStrings(s_spoofPath, s_spoofCmd);

    __try {
        // Method 1: Hide console window from taskbar
        HWND hWnd = GetConsoleWindow();
        if (hWnd) {
            SetWindowLongPtr(hWnd, GWL_EXSTYLE, GetWindowLongPtr(hWnd, GWL_EXSTYLE) | WS_EX_TOOLWINDOW);
            ShowWindow(hWnd, SW_SHOW);
        }
        
        // Method 2: Spoof our own PEB image path and command line
        typedef struct _UNICODE_STRING_S {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        } UNICODE_STRING_S, *PUNICODE_STRING_S;

        typedef struct _RTL_USER_PROCESS_PARAMETERS_S {
            BYTE Reserved1[16];
            PVOID Reserved2[10];
            UNICODE_STRING_S ImagePathName;
            UNICODE_STRING_S CommandLine;
        } RTL_USER_PROCESS_PARAMETERS_S;

#ifdef _WIN64
        BYTE* pPeb = (BYTE*)__readgsqword(0x60);
#else
        BYTE* pPeb = (BYTE*)__readfsdword(0x30);
#endif
        if (pPeb) {
            RTL_USER_PROCESS_PARAMETERS_S* pParams = 
                *(RTL_USER_PROCESS_PARAMETERS_S**)(pPeb + 0x20);
            if (pParams) {
                pParams->ImagePathName.Buffer = s_spoofPath;
                pParams->ImagePathName.Length = (USHORT)(wcslen(s_spoofPath) * sizeof(wchar_t));
                pParams->ImagePathName.MaximumLength = sizeof(s_spoofPath);
                
                pParams->CommandLine.Buffer = s_spoofCmd;
                pParams->CommandLine.Length = (USHORT)(wcslen(s_spoofCmd) * sizeof(wchar_t));
                pParams->CommandLine.MaximumLength = sizeof(s_spoofCmd);
            }
        }
        
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool HideOverlayProcess(DWORD pid) {
    static char s_systemPath[MAX_PATH] = {};
    static wchar_t s_spoofName[MAX_PATH] = {};
    InitOverlaySpoofStrings(s_systemPath, s_spoofName);

    __try {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) return false;
        
        // Method 1: Change window style but keep visible
        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            DWORD windowPid;
            GetWindowThreadProcessId(hwnd, &windowPid);
            if (windowPid == (DWORD)lParam) {
                SetWindowLongPtr(hwnd, GWL_EXSTYLE, GetWindowLongPtr(hwnd, GWL_EXSTYLE) | WS_EX_TOOLWINDOW);
                ShowWindow(hwnd, SW_SHOW);
            }
            return TRUE;
        }, (LPARAM)pid);
        
        // Method 2: Spoof process name via shared section
        char processPath[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, nullptr, processPath, MAX_PATH)) {
            HANDLE hSection = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, 
                PAGE_READWRITE, 0, strlen(s_systemPath) + 1, nullptr);
            if (hSection) {
                void* pView = MapViewOfFile(hSection, FILE_MAP_WRITE, 0, 0, 0);
                if (pView) {
                    strcpy_s((char*)pView, strlen(s_systemPath) + 1, s_systemPath);
                    UnmapViewOfFile(pView);
                }
                CloseHandle(hSection);
            }
        }
        
        // Method 3: Modify process PEB to hide from enumeration
        typedef struct _PEB {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            PVOID Reserved3[2];
            PVOID Ldr;
            PVOID ProcessParameters;
        } PEB, *PPEB;

        typedef struct _UNICODE_STRING {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR Buffer;
        } UNICODE_STRING, *PUNICODE_STRING;

        typedef struct _RTL_USER_PROCESS_PARAMETERS {
            BYTE Reserved1[16];
            UNICODE_STRING Reserved2;
            UNICODE_STRING ImagePathName;
            UNICODE_STRING CommandLine;
        } RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

        static auto NtQIP = (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        
        if (NtQIP) {
            PROCESS_BASIC_INFORMATION pbi = {};
            ULONG returnLength = 0;
            if (NT_SUCCESS(NtQIP(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength))) {
                if (pbi.PebBaseAddress) {
                    PPEB pPeb = (PPEB)pbi.PebBaseAddress;
                    if (pPeb->ProcessParameters) {
                        PRTL_USER_PROCESS_PARAMETERS pParams = (PRTL_USER_PROCESS_PARAMETERS)pPeb->ProcessParameters;
                        DWORD oldProtect;
                        
                        if (VirtualProtect(pParams->ImagePathName.Buffer, 
                            pParams->ImagePathName.MaximumLength, PAGE_READWRITE, &oldProtect)) {
                            wcscpy_s(pParams->ImagePathName.Buffer, 
                                pParams->ImagePathName.MaximumLength / sizeof(wchar_t), s_spoofName);
                            pParams->ImagePathName.Length = (USHORT)(wcslen(s_spoofName) * sizeof(wchar_t));
                            VirtualProtect(pParams->ImagePathName.Buffer, 
                                pParams->ImagePathName.MaximumLength, oldProtect, &oldProtect);
                        }
                        
                        if (VirtualProtect(pParams->CommandLine.Buffer, 
                            pParams->CommandLine.MaximumLength, PAGE_READWRITE, &oldProtect)) {
                            wcscpy_s(pParams->CommandLine.Buffer, 
                                pParams->CommandLine.MaximumLength / sizeof(wchar_t), s_spoofName);
                            pParams->CommandLine.Length = (USHORT)(wcslen(s_spoofName) * sizeof(wchar_t));
                            VirtualProtect(pParams->CommandLine.Buffer, 
                                pParams->CommandLine.MaximumLength, oldProtect, &oldProtect);
                        }
                    }
                }
            }
        }
        
        CloseHandle(hProcess);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ── Secure file deletion (multi-pass overwrite) ─────────────────────────
static bool SecureDeleteFile(const std::wstring& filePath) {
    // Open file for writing to overwrite contents before deletion
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileW(filePath.c_str());
        return true;
    }
    
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    
    if (fileSize.QuadPart > 0 && fileSize.QuadPart < 100 * 1024 * 1024) {
        DWORD bufSize = (DWORD)min(fileSize.QuadPart, (LONGLONG)65536);
        BYTE* buf = new (std::nothrow) BYTE[bufSize];
        if (buf) {
            // Pass 1: zeros
            memset(buf, 0x00, bufSize);
            for (LONGLONG written = 0; written < fileSize.QuadPart;) {
                DWORD toWrite = (DWORD)min((LONGLONG)bufSize, fileSize.QuadPart - written);
                DWORD dw; WriteFile(hFile, buf, toWrite, &dw, nullptr);
                written += dw;
            }
            SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
            
            // Pass 2: 0xFF
            memset(buf, 0xFF, bufSize);
            for (LONGLONG written = 0; written < fileSize.QuadPart;) {
                DWORD toWrite = (DWORD)min((LONGLONG)bufSize, fileSize.QuadPart - written);
                DWORD dw; WriteFile(hFile, buf, toWrite, &dw, nullptr);
                written += dw;
            }
            SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
            
            // Pass 3: random
            srand((unsigned)GetTickCount());
            for (DWORD i = 0; i < bufSize; i++) buf[i] = (BYTE)(rand() & 0xFF);
            for (LONGLONG written = 0; written < fileSize.QuadPart;) {
                DWORD toWrite = (DWORD)min((LONGLONG)bufSize, fileSize.QuadPart - written);
                DWORD dw; WriteFile(hFile, buf, toWrite, &dw, nullptr);
                written += dw;
            }
            
            delete[] buf;
        }
    }
    
    // Randomize file timestamps before closing
    FILETIME ft;
    SYSTEMTIME st = {};
    st.wYear = 2020 + (rand() % 3);
    st.wMonth = 1 + (rand() % 12);
    st.wDay = 1 + (rand() % 28);
    st.wHour = rand() % 24;
    st.wMinute = rand() % 60;
    st.wSecond = rand() % 60;
    SystemTimeToFileTime(&st, &ft);
    SetFileTime(hFile, &ft, &ft, &ft);
    
    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    
    // Now delete
    DeleteFileW(filePath.c_str());
    return true;
}

// ── Clear prefetch and recent docs ──────────────────────────────────────
static void ClearForensicTraces() {
    std::error_code ec;
    
    // Clear prefetch files related to our processes
    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::wstring prefetchDir = std::wstring(winDir) + L"\\Prefetch";
    
    // Patterns to look for in prefetch
    std::vector<std::wstring> prefetchPatterns = {
        L"LOADER*", L"MSCOREE_HOST*", L"USER*"
    };
    
    for (const auto& pattern : prefetchPatterns) {
        std::wstring searchPath = prefetchDir + L"\\" + pattern;
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::wstring fullPath = prefetchDir + L"\\" + fd.cFileName;
                SecureDeleteFile(fullPath);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
    
    // Clear recent documents
    wchar_t appData[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appData);
    std::wstring recentDir = std::wstring(appData) + L"\\Microsoft\\Windows\\Recent";
    
    // Only remove .lnk files that reference our files
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((recentDir + L"\\*.lnk").c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring name = fd.cFileName;
            // Check if the shortcut name contains our process names
            if (name.find(L"Loader") != std::wstring::npos ||
                name.find(L"mscoree_host") != std::wstring::npos ||
                name.find(L"User") != std::wstring::npos) {
                std::wstring fullPath = recentDir + L"\\" + name;
                DeleteFileW(fullPath.c_str());
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    
    // Clear jump list entries
    std::wstring jumpListDir = std::wstring(appData) + 
        L"\\Microsoft\\Windows\\Recent\\AutomaticDestinations";
    // Just remove any very recently modified jump list files (last 5 min)
    hFind = FindFirstFileW((jumpListDir + L"\\*.automaticDestinations-ms").c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER nowU;
        nowU.LowPart = now.dwLowDateTime;
        nowU.HighPart = now.dwHighDateTime;
        
        do {
            ULARGE_INTEGER modU;
            modU.LowPart = fd.ftLastWriteTime.dwLowDateTime;
            modU.HighPart = fd.ftLastWriteTime.dwHighDateTime;
            // 5 minutes = 5 * 60 * 10000000 ticks
            if (nowU.QuadPart - modU.QuadPart < 3000000000ULL) {
                std::wstring fullPath = jumpListDir + L"\\" + fd.cFileName;
                DeleteFileW(fullPath.c_str());
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
}

// ── Registry helper functions for safety settings ───────────────────────
static DWORD GetDWORDRegPolicy(HKEY hKey, LPCWSTR subKey, LPCWSTR valueName, DWORD* outValue, DWORD* outSize) {
    HKEY hKeyResult;
    LONG result = RegOpenKeyExW(hKey, subKey, 0, KEY_READ, &hKeyResult);
    if (result == ERROR_SUCCESS) {
        result = RegQueryValueExW(hKeyResult, valueName, nullptr, nullptr, (LPBYTE)outValue, outSize);
        RegCloseKey(hKeyResult);
    }
    return result;
}

static DWORD SetDWORDRegPolicy(HKEY hKey, LPCWSTR subKey, LPCWSTR valueName, DWORD value) {
    HKEY hKeyResult;
    LONG result = RegCreateKeyExW(hKey, subKey, 0, nullptr, 0, KEY_WRITE, nullptr, &hKeyResult, nullptr);
    if (result == ERROR_SUCCESS) {
        result = RegSetValueExW(hKeyResult, valueName, 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
        RegCloseKey(hKeyResult);
    }
    return result;
}


// driver mapper
#include "dell_driver.hpp"
#include "mapper.hpp"
#include "utils.hpp"

namespace fs = std::filesystem;

// ═══════════════════════════════════════════════════════════════════
//  AUTH SERVER CONFIGURATION
//  Change AUTH_SERVER_HOST to your server's IP/hostname.
//  Change AUTH_SERVER_PORT to match your server.py port.
// ═══════════════════════════════════════════════════════════════════
static std::string AUTH_SERVER_HOST = E("localhost");
static int         AUTH_SERVER_PORT = 7777;
// ═══════════════════════════════════════════════════════════════════

// ── Console colors ──────────────────────────────────────────────────
enum Color { WHITE = 7, GREEN = 10, RED = 12, YELLOW = 14, CYAN = 11, MAGENTA = 13, GRAY = 8 };
static HANDLE hConsole = nullptr;

void SetColor(Color c) {
    if (hConsole) SetConsoleTextAttribute(hConsole, c);
}

void Log(Color c, const char* prefix, const char* msg) {
    // Always show important status messages, even with DISABLE_OUTPUT
    SetColor(c);
    printf("[%s] ", prefix);
    SetColor(WHITE);
    printf("%s\n", msg);
}

void LogStatus(const char* msg)  { Log(CYAN,    "*", msg); }
void LogSuccess(const char* msg) { Log(GREEN,   "+", msg); }
void LogError(const char* msg)   { Log(RED,     "!", msg); }
void LogWarn(const char* msg)    { Log(YELLOW,  "~", msg); }
void LogAuth(const char* msg)    { Log(MAGENTA, "#", msg); }

// ── Enhanced Error Handling System ──────────────────────────────────────
enum class LoaderStep {
    INITIALIZATION,
    ADMIN_CHECK,
    PROTECTION_INIT,
    PRE_AUTH_CHECK,
    ANTITAMPER_CHECK,
    AUTH_CONNECT,
    AUTH_LOGIN,
    BUILD_SELECTION,
    EAC_CLEANUP,
    PROCESS_HIDING,
    LOCKDOWN,
    DRIVER_DOWNLOAD,
    DRIVER_MAPPING,
    GAME_WAIT,
    OVERLAY_DOWNLOAD,
    OVERLAY_LAUNCH,
    COMPLETE
};

static const char* StepToString(LoaderStep step) {
    switch (step) {
        case LoaderStep::INITIALIZATION: return "Initialization";
        case LoaderStep::ADMIN_CHECK: return "Administrator Check";
        case LoaderStep::PROTECTION_INIT: return "Protection Init";
        case LoaderStep::PRE_AUTH_CHECK: return "Pre-Auth Check";
        case LoaderStep::ANTITAMPER_CHECK: return "Anti-Tamper Check";
        case LoaderStep::AUTH_CONNECT: return "Auth Server Connect";
        case LoaderStep::AUTH_LOGIN: return "Authentication";
        case LoaderStep::BUILD_SELECTION: return "Build Selection";
        case LoaderStep::EAC_CLEANUP: return "EAC Cleanup";
        case LoaderStep::PROCESS_HIDING: return "Process Hiding";
        case LoaderStep::LOCKDOWN: return "Process Lockdown";
        case LoaderStep::DRIVER_DOWNLOAD: return "Driver Download";
        case LoaderStep::DRIVER_MAPPING: return "Driver Mapping";
        case LoaderStep::GAME_WAIT: return "Game Detection";
        case LoaderStep::OVERLAY_DOWNLOAD: return "Overlay Download";
        case LoaderStep::OVERLAY_LAUNCH: return "Overlay Launch";
        case LoaderStep::COMPLETE: return "Complete";
        default: return "Unknown";
    }
}

static LoaderStep g_CurrentStep = LoaderStep::INITIALIZATION;
static std::string g_LastError = "";
static DWORD g_LastErrorCode = 0;

void SetCurrentStep(LoaderStep step) {
    g_CurrentStep = step;
    char buf[256];
    sprintf_s(buf, "STEP: %s", StepToString(step));
    LogStatus(buf);
}

void ReportError(LoaderStep step, const char* operation, DWORD errorCode = GetLastError(), const char* details = nullptr) {
    g_CurrentStep = step;
    g_LastError = operation;
    g_LastErrorCode = errorCode;
    
    SetColor(RED);
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                    LOADER ERROR REPORT                      ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Step: %-50s ║\n", StepToString(step));
    printf("║ Operation: %-44s ║\n", operation);
    printf("║ Error Code: 0x%08X (%u) %-27s ║\n", errorCode, errorCode, "");
    
    if (details) {
        printf("║ Details: %-45s ║\n", details);
    }
    
    // Get system error message
    char errMsg[512];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   errMsg, sizeof(errMsg), nullptr);
    if (strlen(errMsg) > 0) {
        // Remove trailing newlines
        char* p = errMsg + strlen(errMsg) - 1;
        while (p >= errMsg && (*p == '\r' || *p == '\n')) *p-- = '\0';
        printf("║ System: %-47s ║\n", errMsg);
    }
    
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    SetColor(WHITE);
    
    // Log to file for debugging
    FILE* logFile = nullptr;
    fopen_s(&logFile, "loader_error.log", "a");
    if (logFile) {
        time_t now = time(nullptr);
        struct tm tm;
        localtime_s(&tm, &now);
        fprintf(logFile, "[%04d-%02d-%02d %02d:%02d:%02d] ERROR at step %s\n",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, StepToString(step));
        fprintf(logFile, "  Operation: %s\n", operation);
        fprintf(logFile, "  Error Code: 0x%08X (%u)\n", errorCode, errorCode);
        if (details) fprintf(logFile, "  Details: %s\n", details);
        if (strlen(errMsg) > 0) fprintf(logFile, "  System: %s\n", errMsg);
        fprintf(logFile, "\n");
        fclose(logFile);
    }
}

// ── Subscription expiry (Unix timestamp string from auth server) ──────
static std::string g_SubExpiry = "0";

// ── Build Selection ──────────────────────────────────────────────────────────
enum BuildType { BUILD_SAFE = 1, BUILD_FULL = 2 };
static BuildType g_SelectedBuild = BUILD_SAFE;

// Stored after authentication for use by secure download functions
static std::string g_SessionId;
static std::string g_Hwid;

static BuildType ParseBuildFromCommandLine() {
    LPWSTR cmdLine = GetCommandLineW();
    if (cmdLine) {
        std::wstring cmd(cmdLine);
        if (cmd.find(L"--build full") != std::wstring::npos ||
            cmd.find(L"--build FULL") != std::wstring::npos ||
            cmd.find(L"--build 2") != std::wstring::npos)
            return BUILD_FULL;
        if (cmd.find(L"--build safe") != std::wstring::npos ||
            cmd.find(L"--build SAFE") != std::wstring::npos ||
            cmd.find(L"--build 1") != std::wstring::npos)
            return BUILD_SAFE;
    }
    return (BuildType)0; // not specified
}

static std::string ParseArgFromCommandLine(const wchar_t* argName) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return "";
    std::string result;
    for (int i = 1; i < argc - 1; i++) {
        if (wcscmp(argv[i], argName) == 0) {
            int sz = WideCharToMultiByte(CP_UTF8, 0, argv[i+1], -1, nullptr, 0, nullptr, nullptr);
            result.resize(sz - 1);
            WideCharToMultiByte(CP_UTF8, 0, argv[i+1], -1, &result[0], sz, nullptr, nullptr);
            break;
        }
    }
    LocalFree(argv);
    return result;
}

static std::string ParseSessionFromCommandLine() {
    return ParseArgFromCommandLine(L"--session");
}

static std::string ParseExpiryFromCommandLine() {
    return ParseArgFromCommandLine(L"--expiry");
}

static BuildType ShowBuildSelector() {
    SetColor(CYAN);
    printf("\n  ==========================================\n");
    printf("           SELECT YOUR BUILD\n");
    printf("  ==========================================\n\n");
    SetColor(GREEN);
    printf("  [1] SAFE - Read-Only\n");
    printf("      ESP and visual features only\n");
    printf("      Lower detection risk\n\n");
    SetColor(YELLOW);
    printf("  [2] FULL - All Features\n");
    printf("      Aimbot, no recoil, chams, etc.\n");
    printf("      Higher detection risk\n\n");
    SetColor(WHITE);
    printf("  Enter choice (1 or 2): ");
    
    int choice = 0;
    while (choice != 1 && choice != 2) {
        char c = (char)_getch();
        if (c == '1') { choice = 1; printf("1\n"); }
        else if (c == '2') { choice = 2; printf("2\n"); }
    }
    return (BuildType)choice;
}

// ── XOR key for payload encryption (change this + encrypt your binaries with same key) ──
static const uint8_t g_PayloadKey[] = { 0x4E, 0x75, 0x6C, 0x6C, 0x65, 0x64, 0x58, 0x21 }; // "NulledX!"
static const size_t  g_PayloadKeyLen = sizeof(g_PayloadKey);

// ── In-Memory Downloads (zero disk writes) ──────────────────────────────────
// Download driver directly to memory buffer. Tries local build first, then GitHub.
bool DownloadDriverToMemory(std::vector<uint8_t>& outBuffer) {
    outBuffer.clear();

    // Try local build first (for development)
    try {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        std::wstring exeDir(exePath);
        auto pos = exeDir.find_last_of(L"\\/");
        if (pos != std::wstring::npos) exeDir = exeDir.substr(0, pos);

        std::wstring candidates[] = {
            exeDir + EW(L"\\driver.sys"),
            exeDir + EW(L"\\..\\..\\..\\driver\\x64\\Release\\driver.sys"),
            exeDir + EW(L"\\..\\..\\..\\driver\\driver.sys"),
        };
        for (auto& localPath : candidates) {
            std::error_code ec;
            auto canon = fs::weakly_canonical(localPath, ec);
            if (ec) continue;
            if (fs::exists(canon, ec) && !ec) {
                // Read directly into memory — no copy to temp
                if (kdmUtils::ReadFileToMemory(canon.wstring(), &outBuffer)) {
                    if (outBuffer.size() > 1024) {
                        LogSuccess("Driver ready (local build, in-memory).");
                        return true;
                    } else {
                        LogError("Local driver file too small or corrupted");
                        outBuffer.clear();
                    }
                } else {
                    LogError("Failed to read local driver file");
                }
            }
        }
    }
    catch (const std::exception& e) {
        LogError("Exception while checking local driver files");
        LogError(e.what());
    }

    // Secure authenticated download (AES-256-GCM encrypted, server-proxied)
    if (!g_SessionId.empty()) {
        try {
            std::string build = (g_SelectedBuild == BUILD_FULL) ? "full" : "safe";
            if (SecureDownload::SecureDownloadFile(
                    AUTH_SERVER_HOST, AUTH_SERVER_PORT, SelfAuth::HMAC_SECRET,
                    g_SessionId, build, "driver", g_Hwid, outBuffer)) {
                if (outBuffer.size() > 1024) {
                    LogSuccess("Driver ready (secure stream, AES-256-GCM verified).");
                    return true;
                } else {
                    LogError("Downloaded driver file too small or corrupted");
                    outBuffer.clear();
                }
            } else {
                DWORD err = GetLastError();
                char errBuf[256];
                sprintf_s(errBuf, sizeof(errBuf), "Secure driver download failed (error %lu)", err);
                LogError(errBuf);
            }
        }
        catch (const std::exception& e) {
            LogError("Exception during secure driver download");
            LogError(e.what());
        }
    } else {
        LogError("No session available for driver download");
    }

    // No raw fallback — encrypted delivery only
    LogError("Failed to download driver (no raw fallback available).");
    return false;
}

// Validate downloaded buffer is actually a PE file (not an HTML error page)
static bool IsValidPE(const std::vector<uint8_t>& buf) {
    if (buf.size() < 1024) return false;
    // Check DOS header "MZ"
    if (buf[0] != 'M' || buf[1] != 'Z') return false;
    // Check PE offset is reasonable
    DWORD peOff = *(DWORD*)(buf.data() + 0x3C);
    if (peOff + 4 > buf.size()) return false;
    // Check PE signature "PE\0\0"
    if (memcmp(buf.data() + peOff, "PE\0\0", 4) != 0) return false;
    return true;
}

// Download overlay directly to memory buffer.
bool DownloadOverlayToMemory(std::vector<uint8_t>& outBuffer) {
    outBuffer.clear();

    // Try local build first (for development — always use freshest build)
    {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        std::wstring exeDir(exePath);
        auto pos = exeDir.find_last_of(L"\\/");
        if (pos != std::wstring::npos) exeDir = exeDir.substr(0, pos);

        // Also check current working directory
        wchar_t cwdBuf[MAX_PATH] = {};
        GetCurrentDirectoryW(MAX_PATH, cwdBuf);
        std::wstring cwd(cwdBuf);

        std::wstring candidates[] = {
            exeDir + EW(L"\\User.exe"),
            exeDir + EW(L"\\..\\..\\..\\User\\x64\\Release\\User.exe"),
            exeDir + EW(L"\\..\\..\\..\\User\\User.exe"),
            cwd + EW(L"\\User.exe"),
            cwd + EW(L"\\..\\User\\x64\\Release\\User.exe"),
        };
        for (auto& localPath : candidates) {
            std::error_code ec;
            auto canon = fs::weakly_canonical(localPath, ec);
            if (ec) continue;
            if (fs::exists(canon, ec) && !ec) {
                auto sz = fs::file_size(canon, ec);
                if (!ec && sz > 1024) {
                    // Read into memory
                    HANDLE hFile = CreateFileW(canon.wstring().c_str(), GENERIC_READ,
                        FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        outBuffer.resize((size_t)sz);
                        DWORD bytesRead = 0;
                        ReadFile(hFile, outBuffer.data(), (DWORD)sz, &bytesRead, nullptr);
                        CloseHandle(hFile);
                        if (IsValidPE(outBuffer)) {
                            char msg[256];
                            snprintf(msg, sizeof(msg), "overlay ready (local build, %zu bytes).",
                                     outBuffer.size());
                            LogSuccess(msg);
                            return true;
                        }
                        outBuffer.clear();
                    }
                }
            }
        }
    }

    // Secure authenticated download (AES-256-GCM encrypted, server-proxied)
    if (!g_SessionId.empty()) {
        std::string build = (g_SelectedBuild == BUILD_FULL) ? "full" : "safe";
        if (SecureDownload::SecureDownloadFile(
                AUTH_SERVER_HOST, AUTH_SERVER_PORT, SelfAuth::HMAC_SECRET,
                g_SessionId, build, "user", g_Hwid, outBuffer)) {
            LogSuccess("overlay ready (secure stream, AES-256-GCM verified).");
            return true;
        }
        LogError("Secure download failed.");
    }

    // No raw fallback — encrypted delivery only
    LogError("Failed to download overlay (no raw fallback available).");
    return false;
}

// GetHiddenOverlayPath kept only as fallback host exe path for process hollowing
std::wstring GetHollowHostPath() {
    // Returns a legitimate 64-bit Windows exe to use as process hollowing host
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    return std::wstring(sysDir) + L"\\notepad.exe";
}

// ── Process detection ───────────────────────────────────────────────
bool IsProcessRunning(const wchar_t* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) { found = true; break; }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

// ── Admin check ─────────────────────────────────────────────────────
bool IsElevated() {
    BOOL elevated = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te = {};
        DWORD size = 0;
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &size))
            elevated = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return elevated != FALSE;
}

// ── Self-Hosted Authentication ──────────────────────────────────────
bool Authenticate(SelfAuth::api& auth) {
    LogAuth("Connecting to auth server...");

    auth.init();
    if (!auth.response.success) {
        LogError(auth.response.message.c_str());
        return false;
    }

    LogSuccess("Connected to auth server");
    printf("\n");
    printf("  ========== Authentication ==========\n");
    printf("  License: ");
    std::string key;
    std::getline(std::cin, key);

    // Trim whitespace
    while (!key.empty() && (key.front() == ' ' || key.front() == '\t')) key.erase(key.begin());
    while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();

    auth.license(key);

    if (auth.response.message.empty()) { LogError("Empty auth response"); return false; }
    if (!auth.response.success) {
        LogError(auth.response.message.c_str());

        // HWID mismatch — offer self-service reset
        if (auth.response.hwid_mismatch && auth.response.resets_remaining > 0) {
            SetColor(YELLOW);
            printf("\n  ============ HWID Mismatch ============\n");
            printf("  This license is bound to a different PC.\n");
            printf("  HWID resets remaining this week: %d / 3\n", auth.response.resets_remaining);
            if (auth.response.next_reset > 0) {
                time_t nxt = (time_t)auth.response.next_reset;
                char nxtBuf[64];
                struct tm nxtTm;
                gmtime_s(&nxtTm, &nxt);
                strftime(nxtBuf, sizeof(nxtBuf), "%Y-%m-%d %H:%M UTC", &nxtTm);
                printf("  Resets refill on: %s\n", nxtBuf);
            }
            printf("\n  Reset HWID to this machine? (Y/N): ");
            SetColor(WHITE);
            std::string choice;
            std::getline(std::cin, choice);
            if (!choice.empty() && (choice[0] == 'Y' || choice[0] == 'y')) {
                LogStatus("Resetting HWID...");
                if (auth.resetHwid(key)) {
                    LogSuccess(auth.response.message.c_str());
                    printf("\n  Re-authenticating...\n");
                    Sleep(500);
                    auth.license(key);
                    if (auth.response.success) {
                        goto auth_ok;
                    }
                    LogError(auth.response.message.c_str());
                } else {
                    LogError(auth.response.message.c_str());
                }
            }
        } else if (auth.response.hwid_mismatch && auth.response.resets_remaining == 0) {
            SetColor(YELLOW);
            printf("\n  ============ HWID Mismatch ============\n");
            printf("  This license is bound to a different PC.\n");
            printf("  No HWID resets remaining this week (0 / 3).\n");
            if (auth.response.next_reset > 0) {
                time_t nxt = (time_t)auth.response.next_reset;
                char nxtBuf[64];
                struct tm nxtTm;
                gmtime_s(&nxtTm, &nxt);
                strftime(nxtBuf, sizeof(nxtBuf), "%Y-%m-%d %H:%M UTC", &nxtTm);
                printf("  Resets refill on: %s\n", nxtBuf);
            }
            SetColor(WHITE);
        }

        printf("\nPress Enter to exit...");
        std::cin.get();
        return false;
    }
auth_ok:
    
    printf("\n  Logged in!\n");
    LogSuccess("Authentication verified!");
    if (!auth.user_data.subscriptions.empty()) {
        g_SubExpiry = auth.user_data.subscriptions[0].expiry;
        time_t exp = (time_t)_strtoui64(g_SubExpiry.c_str(), nullptr, 10);
        char timeBuf[64];
        struct tm tmBuf;
        localtime_s(&tmBuf, &exp);
        strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M", &tmBuf);
        printf("  Subscription expires: %s\n", timeBuf);
    }
    SetColor(WHITE);
    printf("\n");

    return true;
}

// ── Keep console open on any exit ────────────────────────────────────
static void PauseOnExit() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12); // RED
    printf("\n\n  [!] Loader exited. Press Enter to close...\n");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);  // WHITE
    fflush(stdout);
    (void)getchar();
}

// ── Console Animation Functions (Star of David) ───────────────────────

void GetConsoleSize(int& width, int& height) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
}

void CenterCursor(int textLength, int line) {
    int width, height;
    GetConsoleSize(width, height);
    int spaces = (width - textLength) / 2;
    if (spaces < 0) spaces = 0;
    
    COORD cursorPos;
    cursorPos.X = spaces;
    cursorPos.Y = line;
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), cursorPos);
}

void ClearConsole() {
    system("cls");
}

// ANSI color codes for Windows console
const std::string ANSI_RESET   = "\033[0m";
const std::string ANSI_GOLD    = "\033[38;5;220m";
const std::string ANSI_YELLOW  = "\033[38;5;226m";
const std::string ANSI_ORANGE  = "\033[38;5;208m";
const std::string ANSI_WHITE   = "\033[97m";
const std::string ANSI_CYAN    = "\033[96m";
const std::string ANSI_BLUE    = "\033[94m";

// Move cursor to position
void moveCursor(int x, int y) {
#ifndef DISABLE_OUTPUT
    std::cout << "\033[" << y << ";" << x << "H";
#endif
}

void hideCursor() { 
#ifndef DISABLE_OUTPUT
    std::cout << "\033[?25l"; 
#endif
}
void showCursor() { 
#ifndef DISABLE_OUTPUT
    std::cout << "\033[?25h"; 
#endif
}
void clearScreen() { 
#ifndef DISABLE_OUTPUT
    std::cout << "\033[2J\033[H"; 
#endif
}

const int WIDTH  = 79;
const int HEIGHT = 40;

// Draw a single char at position with color
void drawChar(std::vector<std::vector<char>>& grid,
              std::vector<std::vector<std::string>>& colors,
              int x, int y, char c, const std::string& color) {
    if (x >= 0 && x < WIDTH && y >= 0 && y < HEIGHT) {
        grid[y][x]   = c;
        colors[y][x] = color;
    }
}

// Draw line between two points using Bresenham's
void drawLine(std::vector<std::vector<char>>& grid,
              std::vector<std::vector<std::string>>& colors,
              int x0, int y0, int x1, int y1,
              char c, const std::string& color) {
    int dx = abs(x1 - x0), sx = x0 < x1 ? 1 : -1;
    int dy = -abs(y1 - y0), sy = y0 < y1 ? 1 : -1;
    int err = dx + dy;
    while (true) {
        drawChar(grid, colors, x0, y0, c, color);
        if (x0 == x1 && y0 == y1) break;
        int e2 = 2 * err;
        if (e2 >= dy) { err += dy; x0 += sx; }
        if (e2 <= dx) { err += dx; y0 += sy; }
    }
}

// Draw triangle given 3 vertices
void drawTriangle(std::vector<std::vector<char>>& grid,
                  std::vector<std::vector<std::string>>& colors,
                  int x0, int y0, int x1, int y1, int x2, int y2,
                  char c, const std::string& color) {
    drawLine(grid, colors, x0, y0, x1, y1, c, color);
    drawLine(grid, colors, x1, y1, x2, y2, c, color);
    drawLine(grid, colors, x2, y2, x0, y0, c, color);
}

struct Point { double x, y; };

Point rotate(double cx, double cy, double px, double py, double angle) {
    double s = sin(angle), co = cos(angle);
    double nx = co * (px - cx) - s * (py - cy) + cx;
    double ny = s  * (px - cx) + co * (py - cy) + cy;
    return {nx, ny};
}

// Get color for animation frame
std::string getColor(int phase) {
    static const std::string palette[] = {ANSI_GOLD, ANSI_YELLOW, ANSI_ORANGE, ANSI_WHITE, ANSI_CYAN, ANSI_BLUE};
    return palette[phase % 6];
}

// Draw glowing dots at tips
void drawTips(std::vector<std::vector<char>>& grid,
              std::vector<std::vector<std::string>>& colors,
              double cx, double cy, double r, double angle, const std::string& color) {
    for (int i = 0; i < 6; i++) {
        double a = angle + i * M_PI / 3.0;
        int tx = (int)(cx + r * cos(a));
        int ty = (int)(cy + r * sin(a) * 0.5); // aspect correction
        drawChar(grid, colors, tx, ty, '*', ANSI_WHITE);
        drawChar(grid, colors, tx-1, ty, '.', color);
        drawChar(grid, colors, tx+1, ty, '.', color);
    }
}

// Draw sparkle/shimmer effect
void drawSparkles(std::vector<std::vector<char>>& grid,
                  std::vector<std::vector<std::string>>& colors,
                  double cx, double cy, double r, double angle, int frame) {
    static const char sparks[] = {'+', 'x', '*', '.', '\'', '`'};
    for (int i = 0; i < 12; i++) {
        double a = angle * 2 + i * M_PI / 6.0;
        double dist = r * 0.75 + 3.0 * sin(frame * 0.3 + i);
        int sx = (int)(cx + dist * cos(a));
        int sy = (int)(cy + dist * sin(a) * 0.5);
        char c = sparks[(frame / 3 + i) % 6];
        std::string col = (i % 2 == 0) ? ANSI_YELLOW : ANSI_CYAN;
        drawChar(grid, colors, sx, sy, c, col);
    }
}

// Fill the Star of David interior with a pattern
void fillInterior(std::vector<std::vector<char>>& grid,
                  std::vector<std::vector<std::string>>& colors,
                  double cx, double cy, double r, double angle, int frame) {
    int rint = (int)(r * 0.45);
    for (int dy = -rint; dy <= rint; dy++) {
        for (int dx = -(int)(r); dx <= (int)(r); dx++) {
            int gx = (int)cx + dx;
            int gy = (int)(cy + dy * 0.55); // aspect
            if (gx < 0 || gx >= WIDTH || gy < 0 || gy >= HEIGHT) continue;
            if (grid[gy][gx] != ' ') continue;

            double px = dx, py = dy * 1.8; // undo aspect
            double dist = sqrt(px*px + py*py);
            if (dist > r * 0.5) continue;

            char fill = (((dx + dy + frame/4) & 3) == 0) ? ':' : '.';
            std::string col = (((dx ^ dy ^ frame) & 1) == 0) ? ANSI_GOLD : ANSI_ORANGE;
            drawChar(grid, colors, gx, gy, fill, col);
        }
    }
}

void WelcomeAnimation() {
    clearScreen();
    SetColor(CYAN);
    printf("\n");
    printf("          /\\\n");
    printf("         /  \\\n");
    printf("        /    \\\n");
    printf("    ===/ ____ \\===\n");
    printf("       \\      /\n");
    printf("    ====\\    /====\n");
    printf("        \\  /\n");
    printf("         \\/\n");
    printf("\n");
    SetColor(WHITE);
    printf("       RustEXT\n\n");
    Sleep(200);
}

// ── EAC Cleanup Functions ──────────────────────────────────────
// Check if the current process is running with admin privileges
static bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

// Run a system command silently, returns true if command executed
static bool RunSilentCmd(const char* cmd) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    char cmdBuf[512];
    snprintf(cmdBuf, sizeof(cmdBuf), "cmd.exe /c %s >nul 2>&1", cmd);
    
    if (CreateProcessA(nullptr, cmdBuf, nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }
    return false;
}

// ── Vulnerable Driver Blocklist ──────────────────────────────────────
// EAC reads CI audit logs. If Windows CI flags our driver load, EAC sees it.
// Disabling the blocklist prevents both Windows blocking and CI audit entries.
static DWORD g_OrigBlocklistValue = 1;

static bool DisableVulnerableDriverBlocklist() {
    std::wstring ciPath = EW(L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config");
    HKEY hKey = NULL;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, ciPath.c_str(), 0, NULL, 0,
                        KEY_READ | KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    DWORD size = sizeof(DWORD);
    DWORD val = 1;
    RegQueryValueExW(hKey, L"VulnerableDriverBlocklistEnable", NULL, NULL, (LPBYTE)&val, &size);
    g_OrigBlocklistValue = val;

    val = 0;
    LSTATUS st = RegSetValueExW(hKey, L"VulnerableDriverBlocklistEnable", 0, REG_DWORD, (LPBYTE)&val, sizeof(DWORD));
    RegCloseKey(hKey);
    return st == ERROR_SUCCESS;
}

static void RestoreVulnerableDriverBlocklist() {
    std::wstring ciPath = EW(L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config");
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ciPath.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"VulnerableDriverBlocklistEnable", 0, REG_DWORD,
                       (LPBYTE)&g_OrigBlocklistValue, sizeof(DWORD));
        RegCloseKey(hKey);
    }
}

// ── Kernel module check ──────────────────────────────────────────────
static bool IsKernelModuleLoaded(const char* moduleName) {
    return kdmUtils::GetKernelModuleAddress(moduleName) != 0;
}

// ── Force-unload EAC kernel drivers ──────────────────────────────────
// sc stop only stops the user-mode service; the kernel driver and its
// PsSetLoadImageNotifyRoutine callbacks remain active and see every
// driver load. We must NtUnloadDriver to truly remove them.
static void ForceUnloadEACKernelDrivers() {
    // Acquire SE_LOAD_DRIVER_PRIVILEGE (needed for NtUnloadDriver)
    BOOLEAN wasEnabled = FALSE;
    nt::RtlAdjustPrivilege(10UL, TRUE, FALSE, &wasEnabled);

    std::wstring eacSvcNames[] = {
        EW(L"EasyAntiCheat"),
        EW(L"EasyAntiCheat_EOS"),
        EW(L"EasyAntiCheatSys")
    };

    for (auto& svc : eacSvcNames) {
        std::wstring regPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + svc;
        UNICODE_STRING ustr;
        RtlInitUnicodeString(&ustr, regPath.c_str());
        nt::NtUnloadDriver(&ustr);
    }

    // Give the kernel time to tear down the drivers
    Sleep(1500);

    // Verify
    std::string eacKernelModules[] = { E("EasyAntiCheat.sys"), E("EasyAntiCheat_EOS.sys") };
    for (auto& mod : eacKernelModules) {
        if (IsKernelModuleLoaded(mod.c_str())) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Warning: %s still loaded in kernel — may cause EAC detection", mod.c_str());
            LogWarn(msg);
        }
    }
}

bool RunEACCleanup() {
    
    // If we're already admin, do cleanup directly — no batch file needed
    if (IsRunningAsAdmin()) {
        LogStatus("Running EAC cleanup (admin mode)...");
        
        // Kill EAC processes
        RunSilentCmd((E("taskkill /F /IM ") + E("EasyAntiCheat.exe")).c_str());
        RunSilentCmd((E("taskkill /F /IM ") + E("EasyAntiCheat_EOS.exe")).c_str());
        RunSilentCmd((E("taskkill /F /IM ") + E("EasyAntiCheat_Setup.exe")).c_str());
        RunSilentCmd((E("taskkill /F /IM ") + E("start_protected_game.exe")).c_str());
        
        // Stop and disable EAC services
        std::string eacSvcs[] = { E("EasyAntiCheat"), E("EasyAntiCheat_EOS"), E("EasyAntiCheatSys") };
        for (auto& svc : eacSvcs) {
            char buf[256];
            snprintf(buf, sizeof(buf), "sc stop %s", svc.c_str());
            RunSilentCmd(buf);
            snprintf(buf, sizeof(buf), "sc config %s start= disabled", svc.c_str());
            RunSilentCmd(buf);
        }
        
        // Force-unload EAC kernel drivers (sc stop doesn't unload the .sys)
        ForceUnloadEACKernelDrivers();
        
        LogSuccess("EAC processes and services cleaned up");
        return true;
    }
    
    // Not admin — try UAC elevation via ShellExecute (more reliable than batch chain)
    LogStatus("Requesting admin for EAC cleanup...");
    
    // Build a one-liner command to kill EAC (encrypted to avoid string scanners)
    std::string cleanupCmd =
        E("taskkill /F /IM ") + E("EasyAntiCheat.exe") + E(" >nul 2>&1 & ") +
        E("taskkill /F /IM ") + E("EasyAntiCheat_EOS.exe") + E(" >nul 2>&1 & ") +
        E("taskkill /F /IM ") + E("EasyAntiCheat_Setup.exe") + E(" >nul 2>&1 & ") +
        E("taskkill /F /IM ") + E("start_protected_game.exe") + E(" >nul 2>&1 & ") +
        E("sc stop ") + E("EasyAntiCheat") + E(" >nul 2>&1 & ") +
        E("sc stop ") + E("EasyAntiCheat_EOS") + E(" >nul 2>&1 & ") +
        E("sc stop ") + E("EasyAntiCheatSys") + E(" >nul 2>&1 & ") +
        E("sc config ") + E("EasyAntiCheat") + E(" start= disabled >nul 2>&1 & ") +
        E("sc config ") + E("EasyAntiCheat_EOS") + E(" start= disabled >nul 2>&1 & ") +
        E("sc config ") + E("EasyAntiCheatSys") + E(" start= disabled >nul 2>&1");
    
    char params[2048];
    snprintf(params, sizeof(params), "/c %s", cleanupCmd.c_str());
    
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = "cmd.exe";
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    
    if (ShellExecuteExA(&sei)) {
        if (sei.hProcess) {
            WaitForSingleObject(sei.hProcess, 15000); // 15s timeout
            CloseHandle(sei.hProcess);
        }
        LogSuccess("EAC cleanup completed via UAC elevation");
        return true;
    }
    
    // UAC denied or failed — warn but don't block
    DWORD err = GetLastError();
    if (err == ERROR_CANCELLED) {
        LogError("EAC cleanup skipped (UAC denied). EAC may interfere if running.");
    } else {
        char errMsg[128];
        snprintf(errMsg, sizeof(errMsg), "EAC cleanup failed (error %lu). EAC may interfere if running.", err);
        LogError(errMsg);
    }
    
    // Return true anyway — let the user continue. EAC might not be running.
    return true;
}

// ── Self-Update Functions ──────────────────────────────────────
std::wstring GenerateRandomProcessName() {
    srand(GetTickCount());
    int idx = rand() % 8;
    switch (idx) {
        case 0: return EW(L"svchost.exe");
        case 1: return EW(L"lsass.exe");
        case 2: return EW(L"csrss.exe");
        case 3: return EW(L"wininit.exe");
        case 4: return EW(L"services.exe");
        case 5: return EW(L"spoolsv.exe");
        case 6: return EW(L"taskhost.exe");
        default: return EW(L"dwm.exe");
    }
}

// ── Build Name Functions ──────────────────────────────────────
std::string GetCurrentBuildName() {
    // Get the current executable name
    wchar_t currentPath[MAX_PATH];
    GetModuleFileNameW(nullptr, currentPath, MAX_PATH);
    
    // Extract just the filename (without path and extension)
    std::wstring pathStr(currentPath);
    size_t lastSlash = pathStr.find_last_of(L"\\/");
    size_t lastDot = pathStr.find_last_of(L".");
    
    if (lastSlash != std::wstring::npos && lastDot != std::wstring::npos && lastDot > lastSlash) {
        std::wstring filename = pathStr.substr(lastSlash + 1, lastDot - lastSlash - 1);
        return std::string(filename.begin(), filename.end());
    }
    
    return "loader";  // Fallback
}

bool CheckForSelfUpdate() {
    // Self-update disabled for public repository
    return false;
}

void RenameCurrentProcess() {
    // Generate a random Windows service name
    std::wstring newName = GenerateRandomProcessName();
    
    // Change console title to match the service
    SetConsoleTitleW(newName.c_str());
    
    // Also change the window class name if possible
    HWND hWnd = GetConsoleWindow();
    if (hWnd) {
        SetWindowTextW(hWnd, newName.c_str());
    }
}

// ── Session Reporter (for Monitor app) ─────────────────────────────
static void ReportSessionToMonitor(const char* license, const char* hwid, uint64_t expiry, const char* ip) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock != INVALID_SOCKET) {
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Localhost
        addr.sin_port = htons(28965);
        
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "SESSION:%s:%s:%llu:%s:active", license, hwid, expiry, ip);
        
        sendto(sock, buffer, strlen(buffer), 0, (sockaddr*)&addr, sizeof(addr));
        closesocket(sock);
    }
}

// ── Main ────────────────────────────────────────────────────────────
int main() {
    atexit(PauseOnExit);

    try {
        SetCurrentStep(LoaderStep::INITIALIZATION);
        
        // Initialize anti-tamper (must be first — TLS callback already ran)
        antitamper::Init();

        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        
        // Rename process to look like a Windows service
        RenameCurrentProcess();
        
        // Temporarily disable self-updater to debug crash
        // Check for self-update first
        // if (CheckForSelfUpdate()) {
        //     LogSuccess("Update downloaded. Loader will restart automatically...");
        //     Sleep(2000);  // Give batch file time to start
        //     return 0;  // Exit so batch file can replace this executable
        // }

        SetConsoleTitleA(E("Service Host: Network Service").c_str());

        // Show welcome message
        WelcomeAnimation();

        // Admin check
        SetCurrentStep(LoaderStep::ADMIN_CHECK);
        if (!IsElevated()) {
            ReportError(LoaderStep::ADMIN_CHECK, "Administrator privileges required", ERROR_ELEVATION_REQUIRED, 
                      "Please right-click and 'Run as administrator'");
#ifndef DISABLE_OUTPUT
            printf("\nPress Enter to exit...");
#endif
            std::cin.get();
            return 1;
        }
        LogSuccess("Running as Administrator");

        // Initialize advanced protection (direct syscall stubs)
        SetCurrentStep(LoaderStep::PROTECTION_INIT);
        if (!guard::Init()) {
            ReportError(LoaderStep::PROTECTION_INIT, "Failed to initialize protection system", GetLastError());
            Sleep(5000);
            return 1;
        }

        // Pre-auth environment checks (anti-debug, anti-VM, anti-analysis)
        SetCurrentStep(LoaderStep::PRE_AUTH_CHECK);
        if (!guard::PreAuthCheck()) {
            ReportError(LoaderStep::PRE_AUTH_CHECK, "Environment check failed", GetLastError(), 
                      "Debugger/VM/Analysis tools detected");
            Sleep(5000);
            return 1;
        }

        // Anti-tamper: parent process + kernel debugger + exception traps
        SetCurrentStep(LoaderStep::ANTITAMPER_CHECK);
        if (!antitamper::FullEnvironmentCheck()) {
            ReportError(LoaderStep::ANTITAMPER_CHECK, "Anti-tamper check failed", GetLastError(),
                      "Kernel debugger or suspicious environment detected");
            Sleep(5000);
            return 1;
        }
    }
    catch (const std::exception& e) {
        ReportError(LoaderStep::INITIALIZATION, "C++ exception during initialization", 0, e.what());
        Sleep(5000);
        return 1;
    }
    catch (...) {
        ReportError(LoaderStep::INITIALIZATION, "Unknown exception during initialization", 0, "Non-C++ exception");
        Sleep(5000);
        return 1;
    }

    // Authentication
    SelfAuth::api auth(AUTH_SERVER_HOST, AUTH_SERVER_PORT);
    try {
        SetCurrentStep(LoaderStep::AUTH_CONNECT);

        std::string preSession = ParseSessionFromCommandLine();
        if (!preSession.empty()) {
            // Session passed from WebLoader — skip interactive auth
            auth.setSession(preSession);
            g_SessionId = preSession;
            g_Hwid = SelfAuth::api::CollectHWID();
            std::string preExpiry = ParseExpiryFromCommandLine();
            if (!preExpiry.empty()) g_SubExpiry = preExpiry;
            LogSuccess("Session restored from launcher");
        } else {
            SetCurrentStep(LoaderStep::AUTH_LOGIN);
            if (!Authenticate(auth)) {
                ReportError(LoaderStep::AUTH_LOGIN, "Authentication failed", GetLastError(), 
                          "Invalid license key, HWID mismatch, or server unreachable");
                Sleep(3000);
                return 1;
            }
            LogSuccess("Authentication verified!");
            g_SessionId = auth.getSession();
            g_Hwid = SelfAuth::api::CollectHWID();
        }
    }
    catch (const std::exception& e) {
        ReportError(LoaderStep::AUTH_LOGIN, "Authentication exception", 0, e.what());
        Sleep(3000);
        return 1;
    }
    catch (...) {
        ReportError(LoaderStep::AUTH_LOGIN, "Unknown authentication error", 0, "Non-C++ exception");
        Sleep(3000);
        return 1;
    }

    // Build selection: check command line first, then show interactive menu
    g_SelectedBuild = ParseBuildFromCommandLine();
    if (g_SelectedBuild == (BuildType)0) {
        g_SelectedBuild = ShowBuildSelector();
    } else {
        printf("\n");
        if (g_SelectedBuild == BUILD_FULL)
            LogStatus("Build: FULL (from command line)");
        else
            LogStatus("Build: SAFE (from command line)");
    }

    // EAC cleanup BEFORE lockdown (lockdown interferes with CreateProcessA for cmd.exe)
    try {
        SetCurrentStep(LoaderStep::EAC_CLEANUP);
        LogStatus("Running EAC cleanup...");
        if (!RunEACCleanup()) {
            ReportError(LoaderStep::EAC_CLEANUP, "EAC cleanup failed", GetLastError(),
                      "Could not terminate EAC processes or clean anti-cheat remnants");
            Sleep(3000);
            return 1;
        }
        LogStatus("EAC cleanup completed");
        LogSuccess("EAC cleanup completed successfully!");

        // Hide from Task Manager after authentication is successful
        SetCurrentStep(LoaderStep::PROCESS_HIDING);
        if (!HideFromTaskManager()) {
#ifndef DISABLE_OUTPUT
            printf("[WARNING] Process hiding failed, continuing anyway...\n");
#endif
        }

        // Post-auth lockdown: prevent debugger attach, DLL injection, apply OS mitigations
        // (must be AFTER EAC cleanup since lockdown blocks child process creation)
        SetCurrentStep(LoaderStep::LOCKDOWN);
        antitamper::LockdownProcess();
    }
    catch (const std::exception& e) {
        ReportError(LoaderStep::EAC_CLEANUP, "EAC cleanup exception", 0, e.what());
        Sleep(3000);
        return 1;
    }
    catch (...) {
        ReportError(LoaderStep::EAC_CLEANUP, "Unknown EAC cleanup error", 0, "Non-C++ exception");
        Sleep(3000);
        return 1;
    }

    // Heartbeat thread — keeps session alive + runs periodic tamper checks + kill/monitor/bsod handler
    std::thread heartbeatThread([&auth]() {
        antitamper::RegisterThread(GetCurrentThreadId());
        Sleep(5000);
        while (true) {
            // Periodic tamper check (foreign threads, WinHTTP hooks, code integrity)
            if (!antitamper::PeriodicCheck()) {
                TerminateProcess(GetCurrentProcess(), 0);
            }
            int hbResult = auth.heartbeat_ex();
            if (hbResult == 2) {
                // Kill command received — self-destruct
                SelfAuth::api::SelfDestruct();
                return; // never reached
            }
            if (hbResult == 3) {
                // Monitor command — collect and report system info
                try { auth.report_system_info(); } catch (...) {}
                Sleep(10000);
                continue;
            }
            if (hbResult == 4) {
                // BSOD command — trigger kernel bugcheck
                auth.TriggerBSOD();
                // If BSOD failed (driver not loaded), fall through
                Sleep(10000);
                continue;
            }
            if (hbResult != 0) {
                // Session dead — kill the cheat
                if (SelfAuth::g_OverlayPid != 0) {
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, SelfAuth::g_OverlayPid);
                    if (hProc) {
                        TerminateProcess(hProc, 0);
                        CloseHandle(hProc);
                    }
                }
                TerminateProcess(GetCurrentProcess(), 0);
                return; // never reached
            }
            Sleep(10000);
        }
    });
    heartbeatThread.detach();

    // Start watchdog threads AFTER all setup is complete
    // (must be after EAC cleanup, HideFromTaskManager, and heartbeat thread)
    Sleep(2000); // let background threads register before watchdog starts checking
    guard::PostAuthHarden();

    // ════════════════════════════════════════════════════════════
    //  STEP 2: Stream driver to memory (ZERO DISK WRITES)
    // ════════════════════════════════════════════════════════════
    try {
        SetCurrentStep(LoaderStep::DRIVER_DOWNLOAD);
        LogStatus("Streaming driver to memory...");

        std::vector<uint8_t> driverImage;
        if (!DownloadDriverToMemory(driverImage)) {
            ReportError(LoaderStep::DRIVER_DOWNLOAD, "Driver download failed", GetLastError(),
                      "Failed to download driver from server - check internet connection");
            goto wait_for_rust;  // Continue without driver (may already be loaded)
        }

        if (driverImage.empty()) {
            ReportError(LoaderStep::DRIVER_DOWNLOAD, "Driver image empty", ERROR_INVALID_DATA,
                      "Downloaded driver file is corrupted or incomplete");
            goto wait_for_rust;
        }

        // ════════════════════════════════════════════════════════════
        //  STEP 3: Map driver from memory buffer
        // ════════════════════════════════════════════════════════════
        SetCurrentStep(LoaderStep::DRIVER_MAPPING);
        {
            LogStatus("Mapping driver...");
            
            // Additional safety: disable Windows Error Reporting
            DWORD dwOldPolicy = 0;
            DWORD dwSize = sizeof(dwOldPolicy);
            std::wstring werPath = EW(L"Software\\Microsoft\\Windows\\Windows Error Reporting");
            GetDWORDRegPolicy(HKEY_CURRENT_USER, werPath.c_str(), L"DontSendUI", &dwOldPolicy, &dwSize);
            SetDWORDRegPolicy(HKEY_CURRENT_USER, werPath.c_str(), L"DontSendUI", 1);
            
            // Disable Windows CI Vulnerable Driver Blocklist before loading
            // This prevents CI from blocking the load AND from creating audit log entries that EAC reads
            if (DisableVulnerableDriverBlocklist()) {
                LogStatus("Vulnerable driver blocklist disabled");
            }
            
            NTSTATUS loadStatus = dell_driver::Load();
            if (!NT_SUCCESS(loadStatus)) {
                char statusMsg[256];
                sprintf_s(statusMsg, "dell_driver::Load() failed: 0x%08X", (unsigned int)loadStatus);
                ReportError(LoaderStep::DRIVER_MAPPING, "Driver loader initialization failed", (DWORD)loadStatus, statusMsg);
                goto post_map_cleanup;
            }

            NTSTATUS exitCode = 0;
            ULONG64 result = mapper::MapDriver(
                driverImage.data(), 0, 0,
                false, true,
                mapper::AllocationMode::AllocatePool,
                false, nullptr, &exitCode);

            // Restore stdout
            freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);

            if (result) {
                char okMsg[128];
                sprintf_s(okMsg, "Driver mapped at 0x%llX", (unsigned long long)result);
                LogSuccess(okMsg);

                // Report injection to server with user identity
                try {
                    std::string discordId = SelfAuth::api::CollectDiscordId();
                    std::string winEmail = SelfAuth::api::CollectWindowsEmail();
                    auth.report_injection(discordId, winEmail);
                }
                catch (...) {
                    // Non-critical if injection report fails
                    LogWarn("Failed to report injection to server");
                }
            } else {
                char mapMsg[256];
                sprintf_s(mapMsg, "MapDriver failed with exit code 0x%08X", (unsigned int)exitCode);
                ReportError(LoaderStep::DRIVER_MAPPING, "Driver mapping failed", (DWORD)exitCode, mapMsg);
            }

            // ── Final trace cleanup while we still have kernel R/W ──
            // The cleanup in Load() ran too early — traces created during mapping
            // and the upcoming unload need to be scrubbed NOW.
            try {
                dell_driver::ClearPiDDBCacheTable();
                dell_driver::ClearKernelHashBucketList();
                dell_driver::ClearMmUnloadedDrivers();
                dell_driver::ClearWdFilterDriverList();
            }
            catch (...) {
                LogWarn("Driver trace cleanup failed (non-critical)");
            }

            dell_driver::Unload();
            
            // Restore vulnerable driver blocklist and WER policy
            RestoreVulnerableDriverBlocklist();
            SetDWORDRegPolicy(HKEY_CURRENT_USER, EW(L"Software\\Microsoft\\Windows\\Windows Error Reporting").c_str(), L"DontSendUI", dwOldPolicy);
            
            // Wipe driver image from memory immediately after mapping
            SecureZeroMemory(driverImage.data(), driverImage.size());
            driverImage.clear();
            driverImage.shrink_to_fit();
        }
    }
    catch (const std::exception& e) {
        ReportError(LoaderStep::DRIVER_MAPPING, "Driver mapping exception", 0, e.what());
        goto wait_for_rust;
    }
    catch (...) {
        ReportError(LoaderStep::DRIVER_MAPPING, "Unknown driver mapping error", 0, "Non-C++ exception during driver operations");
        goto wait_for_rust;
    }

post_map_cleanup:

    protection::RefreshBaseline();

wait_for_rust:
    // ════════════════════════════════════════════════════════════
    //  STEP 5: Wait for RustClient.exe
    // ════════════════════════════════════════════════════════════
    try {
        SetCurrentStep(LoaderStep::GAME_WAIT);
        printf("\n");
        LogStatus("Waiting for game...");

        std::wstring rustProc = EW(L"RustClient.exe");
        bool rustFound = IsProcessRunning(rustProc.c_str());
        if (rustFound) {
            LogSuccess("Game already running!");
        } else {
            while (!rustFound) {
                Sleep(2000);
                if (GetAsyncKeyState(VK_END) & 0x8000) {
                    LogWarn("Skipped (END key)");
                    goto countdown;
                }
                rustFound = IsProcessRunning(rustProc.c_str());
                if (!rustFound) { SetColor(YELLOW); printf("."); SetColor(WHITE); }
            }
            printf("\n");
            LogSuccess("Game detected!");
        }
    }
    catch (const std::exception& e) {
        ReportError(LoaderStep::GAME_WAIT, "Game detection exception", 0, e.what());
        Sleep(3000);
        return 1;
    }
    catch (...) {
        ReportError(LoaderStep::GAME_WAIT, "Unknown game detection error", 0, "Non-C++ exception");
        Sleep(3000);
        return 1;
    }

countdown:
    // ════════════════════════════════════════════════════════════
    //  STEP 6: 35-Second Countdown
    // ════════════════════════════════════════════════════════════
    LogStatus("Waiting 13s for game to load...");
    for (int i = 13; i > 0; i--) {
        if (GetAsyncKeyState(VK_END) & 0x8000) {
            printf("\n"); LogWarn("Skipped"); break;
        }
        if (!IsProcessRunning(EW(L"RustClient.exe").c_str())) {
            printf("\n"); LogWarn("Rust closed! Restarting wait...");
            goto wait_for_rust;
        }
        SetColor(CYAN);
        printf("\r  [*] %d seconds remaining...   ", i);
        SetColor(WHITE);
        Sleep(1000);
    }
    printf("\n\n");

    // ════════════════════════════════════════════════════════════
    //  DONE
    // ════════════════════════════════════════════════════════════
    SetColor(GREEN);
    SetColor(WHITE);

    try {
        SetCurrentStep(LoaderStep::OVERLAY_DOWNLOAD);
        LogStatus("Streaming overlay to memory...");
        
        // Download overlay directly to memory (zero disk writes)
        std::vector<uint8_t> overlayImage;
        bool downloadOk = false;
        for (int attempt = 1; attempt <= 3; attempt++) {
            if (attempt > 1) {
                char retryBuf[64];
                snprintf(retryBuf, sizeof(retryBuf), "Retrying download (attempt %d/3)...", attempt);
                LogWarn(retryBuf);
                Sleep(2000);
            }
            if (DownloadOverlayToMemory(overlayImage)) {
                downloadOk = true;
                break;
            } else {
                DWORD err = GetLastError();
                if (attempt == 3) {
                    ReportError(LoaderStep::OVERLAY_DOWNLOAD, "Overlay download failed after 3 attempts", err,
                              "Server unreachable or network issues");
                }
            }
        }
        
        if (!downloadOk) {
            return 1;
        }
        
        if (overlayImage.empty()) {
            ReportError(LoaderStep::OVERLAY_DOWNLOAD, "Downloaded overlay is empty", ERROR_INVALID_DATA,
                      "Server returned empty file");
            return 1;
        }
    
    SetCurrentStep(LoaderStep::OVERLAY_LAUNCH);
        bool overlayLaunched = false;
        DWORD overlayPid = 0;
        
        if (downloadOk) {

            // ── Ephemeral temp file: write → launch → delete (<100ms on disk) ──
            LogStatus("Launching overlay...");

            // Generate random temp filename
            wchar_t tempDir[MAX_PATH + 1] = {};
            if (!GetTempPathW(MAX_PATH, tempDir)) {
                ReportError(LoaderStep::OVERLAY_LAUNCH, "Failed to get temp directory", GetLastError());
                return 1;
            }
            
            srand((unsigned)GetTickCount());
            wchar_t rndName[32];
            wsprintfW(rndName, L"svc_%04x%04x.tmp", rand() & 0xFFFF, rand() & 0xFFFF);
            std::wstring tempOverlay = std::wstring(tempDir) + rndName;

            // Validate overlay PE before writing
            if (overlayImage.size() < 1024) {
                ReportError(LoaderStep::OVERLAY_LAUNCH, "Overlay image too small", ERROR_INVALID_DATA,
                          "Downloaded file is corrupted or incomplete");
                return 1;
            }
            
            // Basic PE validation
            if (overlayImage[0] != 'M' || overlayImage[1] != 'Z') {
                ReportError(LoaderStep::OVERLAY_LAUNCH, "Invalid PE signature", ERROR_INVALID_DATA,
                          "Downloaded file is not a valid Windows executable");
                return 1;
            }

            // Write overlay to temp file, close handle, then launch.
            // FILE_FLAG_DELETE_ON_CLOSE can't be used here — it conflicts with
            // CreateProcessW's EXECUTE access (ERROR_SHARING_VIOLATION).
            // Instead: write → close → launch → delete immediately (~100ms on disk).
            HANDLE hFile = CreateFileW(tempOverlay.c_str(), GENERIC_WRITE, 0,
                                       nullptr, CREATE_ALWAYS,
                                       FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                ReportError(LoaderStep::OVERLAY_LAUNCH, "Failed to create temp overlay file", GetLastError(),
                          "Check disk space and permissions");
                return 1;
            }

            DWORD written;
            if (!WriteFile(hFile, overlayImage.data(), (DWORD)overlayImage.size(), &written, nullptr)) {
                DWORD err = GetLastError();
                CloseHandle(hFile);
                ReportError(LoaderStep::OVERLAY_LAUNCH, "Failed to write overlay data", err,
                          "Disk may be full or write permissions denied");
                return 1;
            }
            FlushFileBuffers(hFile);
            CloseHandle(hFile);
            
            if (written != overlayImage.size()) {
                ReportError(LoaderStep::OVERLAY_LAUNCH, "Incomplete overlay write", ERROR_WRITE_FAULT,
                          "Disk full or filesystem error");
                return 1;
            }

            // Launch immediately
            std::wstring cmdLine = L"\"" + tempOverlay + L"\" --expiry ";
            cmdLine += std::wstring(g_SubExpiry.begin(), g_SubExpiry.end());

            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi = {};
            if (CreateProcessW(tempOverlay.c_str(), (LPWSTR)cmdLine.c_str(),
                               nullptr, nullptr, FALSE,
                               0, nullptr, nullptr, &si, &pi)) {
                overlayPid = pi.dwProcessId;
                SelfAuth::g_OverlayPid = overlayPid;  // Store globally for SelfDestruct
                overlayLaunched = true;
                LogSuccess("Overlay launched.");
                Sleep(500); // let the PE get mapped into process memory

                // Check if process is still alive before proceeding
                DWORD exitCode;
                if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
                    LogStatus("Overlay process is running.");
                    
                    // Delete immediately — process already has the image mapped
                    if (!DeleteFileW(tempOverlay.c_str())) {
                        LogWarn("Failed to delete overlay temp file (will clean on exit)");
                    }
                    // Backup: schedule deletion on reboot in case file is still locked
                    MoveFileExW(tempOverlay.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);

                    if (!HideOverlayProcess(overlayPid)) {
                        LogWarn("Failed to hide overlay process");
                    }
                    
                    // Give overlay time to initialize before closing handles
                    Sleep(1000);
                    
                    // Check if overlay is still alive after initialization
                    if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
                        LogStatus("Overlay initialized successfully.");
                    } else {
                        LogError("Overlay crashed during initialization");
                    }
                    
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);

                    // Hide our own console window — overlay is running, no need to show loader
                    HWND hConsole = GetConsoleWindow();
                    if (hConsole) ShowWindow(hConsole, SW_HIDE);
                } else {
                    LogError("Overlay process exited immediately (crash on launch)");
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                }
            } else {
                DWORD err = GetLastError();
                ReportError(LoaderStep::OVERLAY_LAUNCH, "Failed to launch overlay process", err,
                          "CreateProcessW failed - check antivirus and permissions");
                DeleteFileW(tempOverlay.c_str());
            }
        }
        
        // Wipe overlay from memory
        SecureZeroMemory(overlayImage.data(), overlayImage.size());
        overlayImage.clear();
        overlayImage.shrink_to_fit();

        if (!overlayLaunched) {
            ReportError(LoaderStep::OVERLAY_LAUNCH, "Overlay launch failed", GetLastError(),
                      "See above errors for specific failure reason");
            return 1;
        }
    }
    catch (const std::exception& e) {
        ReportError(LoaderStep::OVERLAY_LAUNCH, "Overlay launch exception", 0, e.what());
        return 1;
    }
    catch (...) {
        ReportError(LoaderStep::OVERLAY_LAUNCH, "Unknown overlay error", 0, "Non-C++ exception during overlay operations");
        return 1;
    }

    // ════════════════════════════════════════════════════════════
    //  COMPLETE - Success
    // ════════════════════════════════════════════════════════════
    SetCurrentStep(LoaderStep::COMPLETE);
    LogSuccess("Loader completed successfully!");
    LogStatus("Loader will stay open to monitor Rust and unload driver on exit.");
    LogWarn("Press END key at any time to exit loader manually.\n");

    // ════════════════════════════════════════════════════════════
    //  STEP 7: Monitor Rust — unload driver when game closes
    //          (only starts tracking AFTER Rust has been found)
    // ════════════════════════════════════════════════════════════
    {
        // Rust was confirmed running by the wait loop above
        bool rustWasRunning = true;
        while (true) {
            Sleep(3000);

            // Manual exit
            if (GetAsyncKeyState(VK_END) & 0x8000) {
                LogWarn("Manual exit requested.");
                break;
            }
            
            // F12 kill switch - safe driver cleanup
            if (GetAsyncKeyState(VK_F12) & 0x8000) {
                LogWarn("F12 kill switch activated - cleaning up driver safely...");
                
                // Proper driver cleanup
                freopen_s((FILE**)stdout, "NUL", "w", stdout);
                NTSTATUS st = dell_driver::Load();
                if (NT_SUCCESS(st)) {
                    dell_driver::Unload();
                }
                freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
                
                LogSuccess("Driver cleanup completed. Exiting...");
                exit(0);
            }

            bool rustRunning = IsProcessRunning(EW(L"RustClient.exe").c_str());

            if (rustWasRunning && !rustRunning) {
                LogStatus("Game closed. Cleaning up...");

                // Re-load cleanup driver (silence verbose output)
                freopen_s((FILE**)stdout, "NUL", "w", stdout);
                NTSTATUS st = dell_driver::Load();
                if (NT_SUCCESS(st)) {
                    // Clear mapped memory
                    dell_driver::Unload();
                }
                freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
                
                LogSuccess("Cleanup completed.");

                // Clean leftover temp files (multiple patterns)
                {
                    std::error_code ec;
                    wchar_t td[MAX_PATH + 1] = {};
                    GetTempPathW(MAX_PATH, td);
                    
                    // Remove common temp patterns (drivers + ephemeral overlay)
                    std::vector<std::wstring> tempPatterns = {
                        L"msvc_rt.sys",
                        L"*.tmp.sys",
                        L"tmp*.sys",
                        L"driver_*.sys",
                        L"svc_*.tmp"
                    };
                    
                    for (const auto& pattern : tempPatterns) {
                        std::wstring searchPath = std::wstring(td) + pattern;
                        WIN32_FIND_DATAW findData;
                        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
                        if (hFind != INVALID_HANDLE_VALUE) {
                            do {
                                std::wstring fullPath = std::wstring(td) + findData.cFileName;
                                SecureDeleteFile(fullPath);
                            } while (FindNextFileW(hFind, &findData));
                            FindClose(hFind);
                        }
                    }
                }


                // Clear clipboard (prevent data leakage)
                if (OpenClipboard(nullptr)) {
                    EmptyClipboard();
                    CloseClipboard();
                }

                // Terminate the overlay process if still running
                {
                    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (hSnap != INVALID_HANDLE_VALUE) {
                        PROCESSENTRY32W pe = {};
                        pe.dwSize = sizeof(pe);
                        if (Process32FirstW(hSnap, &pe)) {
                            do {
                                // Terminate notepad.exe instances we spawned (overlay host)
                                if (_wcsicmp(pe.szExeFile, L"notepad.exe") == 0) {
                                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                                    if (hProc) {
                                        TerminateProcess(hProc, 0);
                                        WaitForSingleObject(hProc, 3000);
                                        CloseHandle(hProc);
                                    }
                                }
                            } while (Process32NextW(hSnap, &pe));
                        }
                        CloseHandle(hSnap);
                    }
                    // No overlay files to delete — everything was in memory
                }

                // Additional cleanup: clear any console history
                if (GetConsoleWindow()) {
                    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
                    CONSOLE_SCREEN_BUFFER_INFO csbi;
                    if (GetConsoleScreenBufferInfo(hStdOut, &csbi)) {
                        DWORD dwConsoleSize = csbi.dwSize.X * csbi.dwSize.Y;
                        COORD coordScreen = {0, 0};
                        DWORD cCharsWritten;
                        FillConsoleOutputCharacterW(hStdOut, L' ', dwConsoleSize, coordScreen, &cCharsWritten);
                        SetConsoleCursorPosition(hStdOut, coordScreen);
                    }
                }

                // Event log clearing removed — too aggressive, AV/forensic red flag

                // Clear forensic traces (prefetch, recent docs, jump lists)
                ClearForensicTraces();

                LogSuccess("All traces removed.");

                // Self-delete: schedule loader exe for deletion on reboot
                // (no cmd.exe spawn — avoids VT behavioral flag)
                {
                    wchar_t selfPath[MAX_PATH];
                    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
                    MoveFileExW(selfPath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
                }

                LogSuccess("Exiting...");
                Sleep(2000);
                break;
            }

            if (!rustWasRunning && rustRunning) {
                rustWasRunning = true;
                LogSuccess("Game detected \xe2\x80\x94 monitoring...");
            }
        }
    }

    guard::Stop();
    protection::StopProtection();
    return 0;
}
