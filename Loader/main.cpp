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

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "ntdll.lib")

#include "skStr.h"
#include "auth.hpp"
#include "ka_utils.hpp"
#include "protection.h"
#include "simple_github_downloader.h"

// ── GitHub Authentication ──────────────────────────────────────
// Removed - using public repository only

// ── Process Hiding Functions ──────────────────────────────────────
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

bool HideFromTaskManager() {
    __try {
        // Method 1: Keep window visible but change style to be less obvious
        HWND hWnd = GetConsoleWindow();
        if (hWnd) {
            // Only change style, don't hide completely
            SetWindowLongPtr(hWnd, GWL_EXSTYLE, GetWindowLongPtr(hWnd, GWL_EXSTYLE) | WS_EX_TOOLWINDOW);
            // Keep window visible - don't use SW_HIDE
            ShowWindow(hWnd, SW_SHOW);
        }
        
        // Method 2: Skip aggressive PEB manipulation for stability
        typedef struct _UNICODE_STRING {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        } UNICODE_STRING, *PUNICODE_STRING;

        typedef struct _PEB_LDR_DATA {
            BYTE Reserved1[8];
            PVOID Reserved2[3];
            LIST_ENTRY InMemoryOrderModuleList;
        } PEB_LDR_DATA, *PPEB_LDR_DATA;

        typedef struct _LDR_DATA_TABLE_ENTRY {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID DllBase;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
        } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

        typedef struct _PEB {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            PVOID Reserved3[2];
            PPEB_LDR_DATA Ldr;
            // ... rest of PEB structure
        } PEB, *PPEB;

#ifdef _WIN64
        PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
        PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

        // DISABLED: PEB module list manipulation too aggressive
        // This causes the loader to disappear completely
        /*
        if (pPeb && pPeb->Ldr) {
            // Hide from module list
            PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
            PLIST_ENTRY entry = head->Flink;
            
            while (entry != head) {
                PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                entry = entry->Flink;
                
                // Skip if this is our module
                if (ldrEntry->DllBase == GetModuleHandleA(nullptr)) {
                    // Remove from the list
                    ldrEntry->InLoadOrderLinks.Flink->Blink = ldrEntry->InLoadOrderLinks.Blink;
                    ldrEntry->InLoadOrderLinks.Blink->Flink = ldrEntry->InLoadOrderLinks.Flink;
                    break;
                }
            }
        }
        */
        
        // DISABLED: Process flag modification too aggressive
        // This can cause instability and makes the process hard to track
        /*
        // Method 3: Set process to be hidden in system queries
        HANDLE hProcess = GetCurrentProcess();
        
        // Hide from process enumeration by modifying process flags
        typedef struct _PROCESS_BASIC_INFORMATION {
            PVOID Reserved1;
            PPEB PebBaseAddress;
            PVOID Reserved2[2];
            ULONG_PTR UniqueProcessId;
            PVOID Reserved3;
        } PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

        static auto NtQIP = (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        
        if (NtQIP) {
            PROCESS_BASIC_INFORMATION pbi = {};
            ULONG returnLength = 0;
            if (NT_SUCCESS(NtQIP(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength))) {
                // Modify PEB flags to hide process
                if (pbi.PebBaseAddress) {
                    // Set flags to indicate process should be hidden
                    // This is a subtle approach that may work in some cases
                    DWORD oldProtect;
                    if (VirtualProtect(pbi.PebBaseAddress, sizeof(PEB), PAGE_READWRITE, &oldProtect)) {
                        // Modify specific flags that affect process visibility
                        ((BYTE*)pbi.PebBaseAddress)[2] |= 0x08; // Set hidden flag
                        VirtualProtect(pbi.PebBaseAddress, sizeof(PEB), oldProtect, &oldProtect);
                    }
                }
            }
        }
        */
        
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool HideOverlayProcess(DWORD pid) {
    __try {
        // Hide the overlay process from task manager
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) return false;
        
        // Method 1: Change window style but keep visible
        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            DWORD windowPid;
            GetWindowThreadProcessId(hwnd, &windowPid);
            if (windowPid == (DWORD)lParam) {
                SetWindowLongPtr(hwnd, GWL_EXSTYLE, GetWindowLongPtr(hwnd, GWL_EXSTYLE) | WS_EX_TOOLWINDOW);
                // Keep window visible - don't use SW_HIDE
                ShowWindow(hwnd, SW_SHOW);
            }
            return TRUE;
        }, (LPARAM)pid);
        
        // Method 2: Spoof process name to appear as legitimate Windows process
        char processPath[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, nullptr, processPath, MAX_PATH)) {
            // Copy legitimate system process path
            char systemPath[MAX_PATH];
            GetSystemDirectoryA(systemPath, MAX_PATH);
            strcat_s(systemPath, "\\svchost.exe");
            
            // Create a section with the spoofed name
            HANDLE hSection = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, 
                PAGE_READWRITE, 0, strlen(systemPath) + 1, nullptr);
            if (hSection) {
                void* pView = MapViewOfFile(hSection, FILE_MAP_WRITE, 0, 0, 0);
                if (pView) {
                    strcpy_s((char*)pView, strlen(systemPath) + 1, systemPath);
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
            // ... rest of PEB
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
                        
                        // Spoof process name to appear as svchost.exe
                        wchar_t spoofedName[] = L"svchost.exe";
                        DWORD oldProtect;
                        
                        if (VirtualProtect(pParams->ImagePathName.Buffer, 
                            pParams->ImagePathName.MaximumLength, PAGE_READWRITE, &oldProtect)) {
                            wcscpy_s(pParams->ImagePathName.Buffer, 
                                pParams->ImagePathName.MaximumLength / sizeof(wchar_t), spoofedName);
                            pParams->ImagePathName.Length = wcslen(spoofedName) * sizeof(wchar_t);
                            VirtualProtect(pParams->ImagePathName.Buffer, 
                                pParams->ImagePathName.MaximumLength, oldProtect, &oldProtect);
                        }
                        
                        if (VirtualProtect(pParams->CommandLine.Buffer, 
                            pParams->CommandLine.MaximumLength, PAGE_READWRITE, &oldProtect)) {
                            wcscpy_s(pParams->CommandLine.Buffer, 
                                pParams->CommandLine.MaximumLength / sizeof(wchar_t), spoofedName);
                            pParams->CommandLine.Length = wcslen(spoofedName) * sizeof(wchar_t);
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

// ── IAT Hook: block KeyAuth's integrity-check thread ─────────────────
// KeyAuth's init() calls CreateThread(0,0,modify,0,0,0) to spawn an
// integrity monitor. We intercept that call and create it SUSPENDED
// so the modify() function never executes.

using CreateThread_t = HANDLE(WINAPI*)(
    LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
    LPVOID, DWORD, LPDWORD);

static CreateThread_t g_OrigCreateThread = nullptr;
static std::atomic<bool> g_blockNextThread{ false };

static HANDLE WINAPI HookedCreateThread(
    LPSECURITY_ATTRIBUTES lpAttr, SIZE_T stackSize,
    LPTHREAD_START_ROUTINE lpStart, LPVOID lpParam,
    DWORD flags, LPDWORD lpId)
{
    // The modify thread is created with all-zero params except lpStart
    if (g_blockNextThread.load() &&
        lpAttr == nullptr && stackSize == 0 &&
        lpParam == nullptr && flags == 0 && lpId == nullptr)
    {
        g_blockNextThread.store(false);
        // Create it suspended so modify() never runs
        return g_OrigCreateThread(lpAttr, stackSize, lpStart, lpParam,
                                  CREATE_SUSPENDED, lpId);
    }
    return g_OrigCreateThread(lpAttr, stackSize, lpStart, lpParam, flags, lpId);
}

static PIMAGE_THUNK_DATA g_patchedThunk = nullptr;

static bool PatchCreateThreadIAT(bool install) {
    HMODULE hMod = GetModuleHandleW(nullptr);
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hMod);
    auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)hMod + dos->e_lfanew);
    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress) return false;

    auto desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>((BYTE*)hMod + importDir.VirtualAddress);
    for (; desc->Name; desc++) {
        const char* dll = (const char*)((BYTE*)hMod + desc->Name);
        if (_stricmp(dll, "kernel32.dll") != 0 && _stricmp(dll, "KERNEL32.dll") != 0 &&
            _stricmp(dll, "KERNEL32.DLL") != 0) continue;

        auto origThunk = reinterpret_cast<PIMAGE_THUNK_DATA>((BYTE*)hMod + desc->OriginalFirstThunk);
        auto thunk     = reinterpret_cast<PIMAGE_THUNK_DATA>((BYTE*)hMod + desc->FirstThunk);

        for (; origThunk->u1.AddressOfData; origThunk++, thunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;
            auto name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                (BYTE*)hMod + origThunk->u1.AddressOfData);
            if (strcmp(name->Name, "CreateThread") != 0) continue;

            DWORD oldProt;
            VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProt);

            if (install) {
                g_OrigCreateThread = reinterpret_cast<CreateThread_t>(thunk->u1.Function);
                thunk->u1.Function = reinterpret_cast<ULONG_PTR>(HookedCreateThread);
                g_patchedThunk = thunk;
            } else if (g_OrigCreateThread) {
                thunk->u1.Function = reinterpret_cast<ULONG_PTR>(g_OrigCreateThread);
            }

            VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProt, &oldProt);
            return true;
        }
    }
    return false;
}

// driver mapper
#include "intel_driver.hpp"
#include "mapper.hpp"
#include "utils.hpp"

namespace fs = std::filesystem;

// ═══════════════════════════════════════════════════════════════════
//  KEYAUTH CONFIGURATION
// ═══════════════════════════════════════════════════════════════════
static std::string KA_APP_NAME   = skCrypt("RustEXT").decrypt();
static std::string KA_OWNER_ID   = skCrypt("RoihLZRo5F").decrypt();
static std::string KA_APP_SECRET = skCrypt("b7b4dc2a11a6c5ff3a48524b833d666a69398b32800d55c93729767e77b45553").decrypt();
static std::string KA_VERSION    = skCrypt("1.0").decrypt();
static std::string KA_API_URL    = skCrypt("https://keyauth.win/api/1.3/").decrypt();
static std::string KA_PATH       = skCrypt("").decrypt();
// ═══════════════════════════════════════════════════════════════════

// ── Hidden session file ───────────────────────────────────────────
static std::string GetHiddenSessionPath() {
    wchar_t appData[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appData);
    std::wstring dir = std::wstring(appData) + L"\\Microsoft\\CLR_Security_Config\\v4.0.0";
    fs::create_directories(dir);
    SetFileAttributesW(dir.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    std::wstring path = dir + L"\\settings.dat";
    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    return std::string(path.begin(), path.end());
}
static const std::string KA_SAVE_FILE = GetHiddenSessionPath();

// ── Console colors ──────────────────────────────────────────────────
enum Color { WHITE = 7, GREEN = 10, RED = 12, YELLOW = 14, CYAN = 11, MAGENTA = 13, GRAY = 8 };
static HANDLE hConsole = nullptr;

void SetColor(Color c) {
    if (hConsole) SetConsoleTextAttribute(hConsole, c);
}

void Log(Color c, const char* prefix, const char* msg) {
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

// ── Key helper ───────────────────────────────────────────────
std::string NormalizeKey(const std::string& key) {
    if (key.empty()) return key;
    if (key.substr(0, 8) == "KEYAUTH-") return key;
    return "KEYAUTH-" + key;
}

// ── Silent file download ──────────────────────────────────
bool DownloadFile(const std::string& encUrl, const std::wstring& outputPath) {
    std::wstring wUrl(encUrl.begin(), encUrl.end());
    DeleteFileW(outputPath.c_str());

    HRESULT hr = URLDownloadToFileW(nullptr, wUrl.c_str(), outputPath.c_str(), 0, nullptr);
    if (FAILED(hr)) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Download failed (0x%08X)", (unsigned)hr);
        LogError(buf);
        return false;
    }

    std::error_code ec;
    auto fileSize = fs::file_size(outputPath, ec);
    if (ec || fileSize < 1024) {
        LogError("Downloaded file too small or missing");
        fs::remove(outputPath, ec);
        return false;
    }
    return true;
}

// ── Simple GitHub Downloads ──────────────────────────────────
bool DownloadDriver(const std::wstring& outputPath) {
    // Download from public GitHub repository
    SimpleGitHubDownloader github("IsaiahNulled", "Needed", "main", "");
    
    if (github.DownloadDriver(outputPath)) {
        LogSuccess("driver ready.");
        return true;
    }
    return false;
}

bool DownloadOverlay(const std::wstring& outputPath) {
    // Download from public GitHub repository
    SimpleGitHubDownloader github("IsaiahNulled", "Needed", "main", "");
    
    if (github.DownloadOverlay(outputPath)) {
        LogSuccess("Executing...");
        return true;
    }
    
    return false;
}

// ── Hidden overlay path ──────────────────────────────────────
std::wstring GetHiddenOverlayPath() {
    wchar_t appData[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appData);
    std::wstring dir = std::wstring(appData) + L"\\Microsoft\\CLR_Security_Config\\v4.0.0";
    fs::create_directories(dir);
    // Set directory as hidden + system
    SetFileAttributesW(dir.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    return dir + L"\\mscoree_host.exe";
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

// ── KeyAuth Authentication ──────────────────────────────────────────
bool Authenticate(KeyAuth::api& ka) {
    LogAuth("Initializing authentication...");

    // Hook CreateThread to block KeyAuth's integrity-check thread
    PatchCreateThreadIAT(true);
    g_blockNextThread.store(true);

    ka.init();
    if (!ka.response.success) {
        LogError("Failed to initialize KeyAuth");
        return false;
    }

    LogSuccess("Connected to auth server");
    printf("\n");
    printf("  ========== Authentication ==========\n");
    printf("  License: ");
    std::string key;
    std::getline(std::cin, key);
    ka.license(NormalizeKey(key), "");

    // Handle 2FA
    if (!ka.response.success && ka.response.message == "2FA code required.") {
        printf("  2FA Code: ");
        std::string tfaCode;
        std::getline(std::cin, tfaCode);
        ka.license(NormalizeKey(key), tfaCode);
    }

    if (ka.response.message.empty()) { LogError("Empty auth response"); return false; }
    if (!ka.response.success) {
        LogError(ka.response.message.c_str());
        printf("\nPress Enter to exit...");
        std::cin.get();
        return false;
    }
    
    printf("\n  Logged in!\n");
    LogSuccess("Authentication verified!");
    if (!ka.user_data.subscriptions.empty()) {
        std::string expiryStr = ka.user_data.subscriptions[0].expiry;
        printf("  Subscription expires: %s\n", expiryStr.c_str());
    }
    SetColor(WHITE);
    printf("\n");

    return true;
}

// ── Keep console open on any exit ────────────────────────────────────
static void PauseOnExit() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12); // RED
    printf("\n\n  [!] Loader exited unexpectedly. Press Enter to close...\n");
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
    std::cout << "\033[" << y << ";" << x << "H";
}

void hideCursor() { std::cout << "\033[?25l"; }
void showCursor() { std::cout << "\033[?25h"; }
void clearScreen() { std::cout << "\033[2J\033[H"; }

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
    printf("\n    Rust cheat\n\n");
    SetColor(WHITE);
    Sleep(200);
}

// ── EAC Cleanup Functions ──────────────────────────────────────
bool RunEACCleanup() {
    
    // Create EAC cleanup batch file
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring batchPath = std::wstring(tempPath) + L"\\eac_cleanup.bat";
    std::wstring adminBatchPath = std::wstring(tempPath) + L"\\eac_cleanup_admin.bat";
    
    // Create the main EAC cleanup batch file
    FILE* batchFile = _wfopen(batchPath.c_str(), L"w");
    if (!batchFile) {
        LogError("Failed to create EAC cleanup batch file");
        return false;
    }
    
    // Write the actual EAC cleanup content
    fwprintf(batchFile, L"@echo off\n");
    fwprintf(batchFile, L"title EAC Cleanup\n");
    fwprintf(batchFile, L"color 0C\n");
    fwprintf(batchFile, L"echo ============================================\n");
    fwprintf(batchFile, L"echo   EAC Service / Driver Killer\n");
    fwprintf(batchFile, L"echo   Run as Administrator!\n");
    fwprintf(batchFile, L"echo ============================================\n");
    fwprintf(batchFile, L"echo.\n");
    fwprintf(batchFile, L":: Check admin\n");
    fwprintf(batchFile, L"net session >nul 2>&1\n");
    fwprintf(batchFile, L"if %%errorlevel%% neq 0 (\n");
    fwprintf(batchFile, L"    echo [!] ERROR: Not running as Administrator!\n");
    fwprintf(batchFile, L"    echo [!] Right-click this file and \"Run as administrator\"\n");
    fwprintf(batchFile, L"    pause\n");
    fwprintf(batchFile, L"    exit /b 1\n");
    fwprintf(batchFile, L")\n");
    fwprintf(batchFile, L"echo [*] Killing EAC processes...\n");
    fwprintf(batchFile, L"taskkill /F /IM EasyAntiCheat.exe >nul 2>&1\n");
    fwprintf(batchFile, L"taskkill /F /IM EasyAntiCheat_EOS.exe >nul 2>&1\n");
    fwprintf(batchFile, L"taskkill /F /IM EasyAntiCheat_Setup.exe >nul 2>&1\n");
    fwprintf(batchFile, L"taskkill /F /IM start_protected_game.exe >nul 2>&1\n");
    fwprintf(batchFile, L"echo [+] Processes killed.\n");
    fwprintf(batchFile, L"echo.\n");
    fwprintf(batchFile, L"echo [*] Stopping EAC services...\n");
    fwprintf(batchFile, L"sc stop EasyAntiCheat >nul 2>&1\n");
    fwprintf(batchFile, L"sc stop EasyAntiCheat_EOS >nul 2>&1\n");
    fwprintf(batchFile, L"sc stop EasyAntiCheatSys >nul 2>&1\n");
    fwprintf(batchFile, L"echo [+] Services stopped.\n");
    fwprintf(batchFile, L"echo.\n");
    fwprintf(batchFile, L"echo [*] Disabling EAC services (prevents auto-restart)...\n");
    fwprintf(batchFile, L"sc config EasyAntiCheat start= disabled >nul 2>&1\n");
    fwprintf(batchFile, L"sc config EasyAntiCheat_EOS start= disabled >nul 2>&1\n");
    fwprintf(batchFile, L"sc config EasyAntiCheatSys start= disabled >nul 2>&1\n");
    fwprintf(batchFile, L"echo [+] Services disabled.\n");
    fwprintf(batchFile, L"echo.\n");
    fwprintf(batchFile, L"echo [*] Unloading EAC kernel driver (EasyAntiCheat.sys)...\n");
    fwprintf(batchFile, L"sc stop EasyAntiCheat >nul 2>&1\n");
    fwprintf(batchFile, L"\n");
    fwprintf(batchFile, L":: Try to find and unload EAC driver variants\n");
    fwprintf(batchFile, L"for %%d in (EasyAntiCheat EasyAntiCheatSys EasyAntiCheat_EOS) do (\n");
    fwprintf(batchFile, L"    sc query %%d >nul 2>&1\n");
    fwprintf(batchFile, L"    if !errorlevel! equ 0 (\n");
    fwprintf(batchFile, L"        sc stop %%d >nul 2>&1\n");
    fwprintf(batchFile, L"        sc delete %%d >nul 2>&1\n");
    fwprintf(batchFile, L"        echo [+] Removed driver: %%d\n");
    fwprintf(batchFile, L"    )\n");
    fwprintf(batchFile, L")\n");
    fwprintf(batchFile, L"echo.\n");
    fwprintf(batchFile, L"echo [*] Checking if EAC is still running...\n");
    fwprintf(batchFile, L"sc query EasyAntiCheat 2>nul | find \"RUNNING\" >nul\n");
    fwprintf(batchFile, L"if %%errorlevel%% equ 0 (\n");
    fwprintf(batchFile, L"    echo [!] WARNING: EAC service is still running!\n");
    fwprintf(batchFile, L"    echo [!] Try rebooting or use a driver unloader.\n");
    fwprintf(batchFile, L") else (\n");
    fwprintf(batchFile, L"    echo [+] EAC is NOT running. You're clean.\n");
    fwprintf(batchFile, L")\n");
    fwprintf(batchFile, L"echo.\n");
    fwprintf(batchFile, L"echo ============================================\n");
    fwprintf(batchFile, L"echo   Done! Load your driver now.\n");
    fwprintf(batchFile, L"echo ============================================\n");
    fwprintf(batchFile, L"echo.\n");
    fwprintf(batchFile, L"pause\n");
    
    fclose(batchFile);
    
    // Create the admin elevation batch file
    FILE* adminBatchFile = _wfopen(adminBatchPath.c_str(), L"w");
    if (!adminBatchFile) {
        LogError("Failed to create admin elevation batch file");
        DeleteFileW(batchPath.c_str());
        return false;
    }
    
    // Write the admin elevation content
    fwprintf(adminBatchFile, L"@echo off\n");
    fwprintf(adminBatchFile, L"echo Requesting administrator privileges for EAC cleanup...\n");
    fwprintf(adminBatchFile, L"powershell -Command \"Start-Process cmd.exe -ArgumentList '/c \"%s\"' -Verb RunAs\"\n", batchPath.c_str());
    
    fclose(adminBatchFile);
    
    // Run the admin elevation batch file
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    std::wstring cmd = L"cmd.exe /c \"" + adminBatchPath + L"\"";
    
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    
    if (CreateProcessW(nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE, 
                      CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        
        // Wait for the admin elevation to complete
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        // Clean up batch files
        DeleteFileW(adminBatchPath.c_str());
        DeleteFileW(batchPath.c_str());
        
        return exitCode == 0;
    } else {
        DWORD error = GetLastError();
        LogError("Failed to start UAC elevation");
        
        // Clean up batch files
        DeleteFileW(adminBatchPath.c_str());
        DeleteFileW(batchPath.c_str());
        return false;
    }
}

// ── Self-Update Functions ──────────────────────────────────────
std::wstring GenerateRandomProcessName() {
    const wchar_t* services[] = {
        L"svchost.exe", L"lsass.exe", L"csrss.exe", L"wininit.exe", 
        L"services.exe", L"spoolsv.exe", L"taskhost.exe", L"dwm.exe"
    };
    
    srand(GetTickCount());
    return services[rand() % (sizeof(services) / sizeof(services[0]))];
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

// ── Main ────────────────────────────────────────────────────────────
int main() {
    atexit(PauseOnExit);

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

    SetConsoleTitleA(skCrypt("Rust Cheat"));

    // Show welcome message
    WelcomeAnimation();

    // Admin check
    if (!IsElevated()) {
        LogError("Not running as Administrator!");
        LogError("Right-click and 'Run as administrator'");
        printf("\nPress Enter to exit...");
        std::cin.get();
        return 1;
    }
    LogSuccess("Running as Administrator");

    // Authentication
    KeyAuth::api ka(KA_APP_NAME, KA_OWNER_ID, KA_VERSION, KA_API_URL, KA_PATH);

    if (!Authenticate(ka)) {
        LogError("Authentication failed. Exiting in 3 seconds...");
        Sleep(3000);
        return 1;
    }
    LogSuccess("Authentication verified!");

    LogStatus("Running EAC cleanup...");
    if (!RunEACCleanup()) {
        LogError("EAC cleanup failed. Cannot continue safely.");
        Sleep(3000);
        return 1;
    }
    LogStatus("EAC cleanup completed");
    LogSuccess("EAC cleanup completed successfully!");

    // Hide from Task Manager after authentication is successful
    if (!HideFromTaskManager()) {
        printf("[WARNING] Process hiding failed, continuing anyway...\n");
    }

    // NOTE: checkAuthenticated() is intentionally NOT started.
    // It calls exit(13) if GlobalFindAtomA fails, which it will since
    // we blocked KeyAuth's modify thread (which normally registers the atom).

    std::thread checkThread([&ka]() {
        Sleep(5000); // Let main flow settle before first check
        ka.check(true);
        if (!ka.response.success) {
            LogWarn("Session check failed — session may have expired");
            return; // Don't kill the whole process
        }
        if (ka.response.isPaid) {
            while (true) {
                Sleep(30000);
                ka.check();
                if (!ka.response.success) {
                    LogWarn("Session expired");
                    return;
                }
            }
        }
    });
    checkThread.detach();

    // ════════════════════════════════════════════════════════════
    //  STEP 2: Download Driver (BEFORE hardening — COM needs PE header)
    // ════════════════════════════════════════════════════════════
    LogStatus("Preparing driver...");
    LogSuccess("");

    wchar_t tempDir[MAX_PATH + 1] = {};
    GetTempPathW(MAX_PATH, tempDir);
    std::wstring driverPath = std::wstring(tempDir) + L"msvc_rt.sys";

    if (!DownloadDriver(driverPath)) {
        LogError("Driver preparation failed. Continuing (driver may be loaded already)...");
        goto wait_for_rust;
    }

    // ════════════════════════════════════════════════════════════
    //  STEP 3: Anti-RE Protection
    // ════════════════════════════════════════════════════════════
    {
        LogStatus("mapping driver...");
        
        // Additional safety: disable Windows Error Reporting
        DWORD dwOldPolicy = 0;
        DWORD dwSize = sizeof(dwOldPolicy);
        GetDWORDRegPolicy(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\Windows Error Reporting", L"DontSendUI", &dwOldPolicy, &dwSize);
        SetDWORDRegPolicy(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\Windows Error Reporting", L"DontSendUI", 1);
        
        // silence verbose driver output
        freopen_s((FILE**)stdout, "NUL", "w", stdout);
        
        NTSTATUS loadStatus = intel_driver::Load();
        if (!NT_SUCCESS(loadStatus)) {
            // Restore stdout before returning
            freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
            LogWarn("Driver may already be loaded. Continuing...");
            goto cleanup_and_wait;
        }

        std::vector<uint8_t> driverImage;
        if (!kdmUtils::ReadFileToMemory(driverPath, &driverImage)) {
            // Restore stdout before returning
            freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
            LogError("Failed to read driver file");
            intel_driver::Unload();
            goto cleanup_and_wait;
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
            LogSuccess("driver mapped.");
        } else {
            LogWarn("driver may already be loaded.");
        }

        intel_driver::Unload();
    }

cleanup_and_wait:
    {
        std::error_code ec;
        fs::remove(driverPath, ec);
        if (!ec) LogSuccess("Temp driver file cleaned");
    }

    protection::RefreshBaseline();

wait_for_rust:
    // ════════════════════════════════════════════════════════════
    //  STEP 5: Wait for RustClient.exe
    // ════════════════════════════════════════════════════════════
    printf("\n");
    LogStatus("Waiting for RustClient.exe...");

    {
        bool rustFound = IsProcessRunning(L"RustClient.exe");
        if (rustFound) {
            LogSuccess("RustClient.exe already running!");
        } else {
            while (!rustFound) {
                Sleep(2000);
                if (GetAsyncKeyState(VK_END) & 0x8000) {
                    LogWarn("Skipped (END key)");
                    goto countdown;
                }
                rustFound = IsProcessRunning(L"RustClient.exe");
                if (!rustFound) { SetColor(YELLOW); printf("."); SetColor(WHITE); }
            }
            printf("\n");
            LogSuccess("RustClient.exe detected!");
        }
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
        if (!IsProcessRunning(L"RustClient.exe")) {
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

    LogStatus("Preparing overlay...");
    std::wstring overlayPath = GetHiddenOverlayPath();
    if (DownloadOverlay(overlayPath)) {
        // Hide the file itself
        SetFileAttributesW(overlayPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

        LogStatus("Launching overlay...");
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb  = L"runas";
        sei.lpFile  = overlayPath.c_str();
        sei.nShow   = SW_SHOW;
        sei.fMask   = SEE_MASK_NOCLOSEPROCESS;
        if (ShellExecuteExW(&sei)) {
            LogSuccess("Overlay launched.");
            Sleep(1000);
            if (sei.hProcess) {
                DWORD pid = GetProcessId(sei.hProcess);
                HideOverlayProcess(pid);
                CloseHandle(sei.hProcess);
            }
        } else {
            LogError("Failed to launch overlay.");
        }
    } else {
        LogError("Failed to download overlay.");
    }

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
                NTSTATUS st = intel_driver::Load();
                if (NT_SUCCESS(st)) {
                    intel_driver::Unload();
                }
                freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
                
                LogSuccess("Driver cleanup completed. Exiting...");
                exit(0);
            }

            bool rustRunning = IsProcessRunning(L"RustClient.exe");

            if (rustWasRunning && !rustRunning) {
                LogStatus("Game closed. Cleaning up...");

                // Re-load cleanup driver (silence verbose output)
                freopen_s((FILE**)stdout, "NUL", "w", stdout);
                NTSTATUS st = intel_driver::Load();
                if (NT_SUCCESS(st)) {
                    // Clear mapped memory
                    intel_driver::Unload();
                }
                freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
                
                LogSuccess("Cleanup completed.");

                // Clean leftover temp files (multiple patterns)
                {
                    std::error_code ec;
                    wchar_t td[MAX_PATH + 1] = {};
                    GetTempPathW(MAX_PATH, td);
                    
                    // Remove common temp driver patterns
                    std::vector<std::wstring> tempPatterns = {
                        L"msvc_rt.sys",
                        L"*.tmp.sys",
                        L"tmp*.sys",
                        L"driver_*.sys"
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

                // Clean up resources
                {
                    std::error_code ec;
                    std::wstring op = GetHiddenOverlayPath();
                    // Terminate process
                    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (hSnap != INVALID_HANDLE_VALUE) {
                        PROCESSENTRY32W pe = {};
                        pe.dwSize = sizeof(pe);
                        if (Process32FirstW(hSnap, &pe)) {
                            do {
                                if (_wcsicmp(pe.szExeFile, L"mscoree_host.exe") == 0) {
                                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
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
                    Sleep(500);
                    SecureDeleteFile(op);
                    // Remove directory
                    std::wstring dir = op.substr(0, op.find_last_of(L'\\'));
                    RemoveDirectoryW(dir.c_str());
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

                // Clear any remaining event logs (optional, requires admin)
                // Note: This is aggressive and may require additional privileges
                try {
                    // Clear application event logs related to our process
                    HANDLE hEventLog = OpenEventLogW(nullptr, L"Application");
                    if (hEventLog) {
                        ClearEventLogW(hEventLog, nullptr);
                        CloseEventLog(hEventLog);
                    }
                } catch (...) {
                    // Silently fail if we don't have permissions
                }

                // Clear forensic traces (prefetch, recent docs, jump lists)
                ClearForensicTraces();

                LogSuccess("All traces removed.");

                // Self-delete: schedule loader exe deletion after exit
                {
                    wchar_t selfPath[MAX_PATH];
                    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
                    // Use cmd /C ping to delay then delete
                    std::wstring cmd = L"cmd.exe /C ping 127.0.0.1 -n 3 > nul & del /f /q \"";
                    cmd += selfPath;
                    cmd += L"\"";
                    STARTUPINFOW si2 = { sizeof(si2) };
                    si2.dwFlags = STARTF_USESHOWWINDOW;
                    si2.wShowWindow = SW_HIDE;
                    PROCESS_INFORMATION pi2 = {};
                    CreateProcessW(nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr,
                                   FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si2, &pi2);
                    if (pi2.hThread) CloseHandle(pi2.hThread);
                    if (pi2.hProcess) CloseHandle(pi2.hProcess);
                }

                LogSuccess("Exiting...");
                Sleep(2000);
                break;
            }

            if (!rustWasRunning && rustRunning) {
                rustWasRunning = true;
                LogSuccess("RustClient.exe detected — monitoring...");
            }
        }
    }

    protection::StopProtection();
    return 0;
}
