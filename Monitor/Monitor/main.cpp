/*
 * RustEXT Monitor — Admin panel for viewing sessions and detecting reverse engineering
 * Features: KeyAuth session viewer, anti-reverse engineering detection, auto-restart on detection
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <winternl.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <conio.h>
#include <cstdio>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ── KeyAuth API (minimal) ───────────────────────────────────────
struct KeyAuthSession {
    std::string license;
    std::string hwid;
    uint64_t expiry;
    std::string status;
    std::string ip;
};

// ── Local Session Monitoring (no API key needed) ───────────────────────
static std::vector<KeyAuthSession> g_activeSessions;
static std::mutex g_sessionsMutex;

// Simple network listener to receive session reports from loaders
static void StartSessionListener() {
    // Create a simple UDP listener on port 28965
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return;
    
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(28965);
    
    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
        printf("[LISTENER] Session monitor listening on port 28965\n");
        
        char buffer[1024];
        sockaddr_in fromAddr;
        int fromLen = sizeof(fromAddr);
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (sockaddr*)&fromAddr, &fromLen);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                
                // Parse simple protocol: "SESSION:license:hwid:expiry:ip"
                if (strncmp(buffer, "SESSION:", 8) == 0) {
                    char* token = strtok(buffer + 8, ":");
                    KeyAuthSession session;
                    
                    if (token) { session.license = token; token = strtok(nullptr, ":"); }
                    if (token) { session.hwid = token; token = strtok(nullptr, ":"); }
                    if (token) { session.expiry = _strtoui64(token, nullptr, 10); token = strtok(nullptr, ":"); }
                    if (token) { session.status = token; token = strtok(nullptr, ":"); }
                    if (token) { session.ip = token; }
                    
                    if (!session.license.empty()) {
                        std::lock_guard<std::mutex> lock(g_sessionsMutex);
                        
                        // Update or add session
                        bool found = false;
                        for (auto& s : g_activeSessions) {
                            if (s.license == session.license) {
                                s = session; // Update existing
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            g_activeSessions.push_back(session);
                        }
                    }
                }
                // Handle "HEARTBEAT:license" to keep sessions alive
                else if (strncmp(buffer, "HEARTBEAT:", 10) == 0) {
                    char* license = buffer + 10;
                    std::lock_guard<std::mutex> lock(g_sessionsMutex);
                    
                    // Update last seen time (simplified - just keep session)
                    for (auto& s : g_activeSessions) {
                        if (s.license == license) {
                            // Session is still alive
                            break;
                        }
                    }
                }
                // Handle "LOGOUT:license" to remove sessions
                else if (strncmp(buffer, "LOGOUT:", 7) == 0) {
                    char* license = buffer + 7;
                    std::lock_guard<std::mutex> lock(g_sessionsMutex);
                    
                    g_activeSessions.erase(
                        std::remove_if(g_activeSessions.begin(), g_activeSessions.end(),
                            [&](const KeyAuthSession& s) { return s.license == license; }),
                        g_activeSessions.end()
                    );
                }
            }
            Sleep(10);
        }
    }
    
    closesocket(sock);
}

static bool FetchKeyAuthSessions(std::vector<KeyAuthSession>& sessions) {
    sessions.clear();
    
    // Method 1: Read local KeyAuth session files
    char appData[MAX_PATH];
    if (GetEnvironmentVariableA("LOCALAPPDATA", appData, MAX_PATH)) {
        std::string sessionDir = std::string(appData) + "\\Microsoft\\FontCache";
        
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA((sessionDir + "\\*.dat").c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::string filePath = sessionDir + "\\" + findData.cFileName;
                
                // Simple JSON parsing for KeyAuth session files
                FILE* f = fopen(filePath.c_str(), "r");
                if (f) {
                    fseek(f, 0, SEEK_END);
                    long size = ftell(f);
                    fseek(f, 0, SEEK_SET);
                    
                    if (size > 0 && size < 10000) { // Reasonable size check
                        char* content = (char*)malloc(size + 1);
                        fread(content, 1, size, f);
                        content[size] = '\0';
                        
                        // Look for license key in JSON
                        char* licenseStart = strstr(content, "\"license\":");
                        if (licenseStart) {
                            licenseStart = strchr(licenseStart, '"');
                            if (licenseStart) {
                                licenseStart++; // Skip opening quote
                                char* licenseEnd = strchr(licenseStart, '"');
                                if (licenseEnd) {
                                    std::string license(licenseStart, licenseEnd - licenseStart);
                                    
                                    KeyAuthSession session;
                                    session.license = license;
                                    session.hwid = "LOCAL_FILE";
                                    session.expiry = 0;
                                    session.status = "active";
                                    session.ip = "LOCAL";
                                    
                                    sessions.push_back(session);
                                }
                            }
                        }
                        
                        free(content);
                    }
                    fclose(f);
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    // Method 2: Add sessions from network listener
    {
        std::lock_guard<std::mutex> lock(g_sessionsMutex);
        for (const auto& session : g_activeSessions) {
            sessions.push_back(session);
        }
    }
    
    return !sessions.empty();
}

// ── Reverse Engineering Detection ──────────────────────────────────
struct DetectionResult {
    bool debugger_detected = false;
    bool vm_detected = false;
    bool analysis_tools = false;
    bool hooked_ntdll = false;
    int threat_score = 0;
    std::vector<std::string> details;
};

static bool CheckForDebugger() {
    // Multiple debugger detection methods
    if (IsDebuggerPresent()) return true;
    
    BOOL isRemote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemote) && isRemote) return true;
    
    // NtQueryInformationProcess check
    typedef NTSTATUS(NTAPI* pNtQueryInfoProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        auto NtQIP = (pNtQueryInfoProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (NtQIP) {
            PVOID debugPort = nullptr;
            ULONG retLen = 0;
            if (NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), &retLen) >= 0) {
                if (debugPort != nullptr) return true;
            }
        }
    }
    
    return false;
}

static bool CheckVM() {
    // CPUID hypervisor bit
    int cpuid[4];
    __cpuid(cpuid, 1);
    if (cpuid[2] >> 31 & 1) return true; // Hypervisor bit
    
    // Check for common VM vendor strings
    __cpuid(cpuid, 0x40000000);
    char vendor[13] = {};
    memcpy(vendor, &cpuid[1], 4);
    memcpy(vendor + 4, &cpuid[2], 4);
    memcpy(vendor + 8, &cpuid[3], 4);
    
    std::string vmVendors[] = {"VMwareVMware", "Microsoft Hv", "XenVMMXenVMM", "KVMKVMKVM"};
    for (const auto& v : vmVendors) {
        if (vendor == v) return true;
    }
    
    return false;
}

static bool CheckAnalysisTools() {
    // Common analysis tool process names
    const char* tools[] = {
        "x32dbg.exe", "x64dbg.exe", "ollydbg.exe", "windbg.exe", "ida.exe", "ida64.exe",
        "processhacker.exe", "procmon.exe", "wireshark.exe", "fiddler.exe", "httpdebugger.exe",
        "cheatengine.exe", "reclass.exe", "x64dbgpy.exe", "scyllahide.exe"
    };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe32 = { sizeof(pe32) };
    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (const char* tool : tools) {
                char szExeFile[MAX_PATH];
                WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, szExeFile, MAX_PATH, nullptr, nullptr);
                if (_stricmp(szExeFile, tool) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return false;
}

static bool CheckNtdllHooks() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;
    
    // Check first few bytes of critical functions for JMP/CALL hooks
    const char* functions[] = {"NtQueryInformationProcess", "NtQuerySystemInformation", "NtReadVirtualMemory"};
    
    for (const char* func : functions) {
        void* addr = GetProcAddress(hNtdll, func);
        if (addr) {
            BYTE* bytes = (BYTE*)addr;
            // Check for common hook patterns (JMP, CALL with relative address)
            if (bytes[0] == 0xE9 || bytes[0] == 0xE8 || bytes[0] == 0xFF) {
                return true;
            }
        }
    }
    
    return false;
}

static DetectionResult PerformFullDetection() {
    DetectionResult result;
    
    if (CheckForDebugger()) {
        result.debugger_detected = true;
        result.threat_score += 10;
        result.details.push_back("Debugger detected");
    }
    
    if (CheckVM()) {
        result.vm_detected = true;
        result.threat_score += 5;
        result.details.push_back("VM environment detected");
    }
    
    if (CheckAnalysisTools()) {
        result.analysis_tools = true;
        result.threat_score += 7;
        result.details.push_back("Analysis tools running");
    }
    
    if (CheckNtdllHooks()) {
        result.hooked_ntdll = true;
        result.threat_score += 8;
        result.details.push_back("ntdll hooks detected");
    }
    
    return result;
}

// ── Auto-Restart Function ──────────────────────────────────────────
static void RestartPC(const std::string& reason, const std::string& targetIP = "") {
    printf("[ALERT] Restarting PC due to: %s\n", reason.c_str());
    
    if (!targetIP.empty()) {
        printf("Target: %s (remote restart)\n", targetIP.c_str());
        
        // Remote restart via WMI (requires admin on target machine)
        std::wstring cmd = L"wmic /node:" + std::wstring(targetIP.begin(), targetIP.end()) + 
                          L" /user:administrator /password:YOUR_PASSWORD os where primary=true reboot";
        
        // For now, use shutdown command (requires admin credentials or same domain)
        std::wstring shutdownCmd = L"shutdown /r /f /m \\\\" + std::wstring(targetIP.begin(), targetIP.end());
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        
        if (CreateProcessW(nullptr, (LPWSTR)shutdownCmd.c_str(), nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            printf("Remote restart command sent to %s\n", targetIP.c_str());
            WaitForSingleObject(pi.hProcess, 5000); // Wait up to 5 seconds
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return;
        } else {
            printf("Failed to send remote restart (error %lu)\n", GetLastError());
            printf("Falling back to local restart...\n");
        }
    }
    
    // Give user a chance to cancel (5 seconds)
    printf("Restarting LOCAL PC in 5 seconds... Press any key to cancel\n");
    for (int i = 5; i > 0; i--) {
        printf("%d... ", i);
        Sleep(1000);
        if (_kbhit()) {
            _getch();
            printf("\nRestart cancelled by user\n");
            return;
        }
    }
    
    // Force local restart
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LUID luid;
        if (LookupPrivilegeValueA(nullptr, "SeShutdownPrivilege", &luid)) {
            TOKEN_PRIVILEGES tp = {};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr)) {
                ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0);
            }
        }
        CloseHandle(hToken);
    }
}

// ── UI Functions ───────────────────────────────────────────────────
static void ClearScreen() {
    system("cls");
}

static void PrintHeader() {
    printf("========================================\n");
    printf("       RustEXT Monitor v1.0\n");
    printf("    Session Viewer & RE Detection\n");
    printf("========================================\n\n");
}

static void PrintSessions(const std::vector<KeyAuthSession>& sessions) {
    printf("Active Sessions (%zu):\n", sessions.size());
    printf("----------------------------------------\n");
    for (const auto& sess : sessions) {
        printf("License: %s\n", sess.license.c_str());
        printf("HWID: %s\n", sess.hwid.c_str());
        printf("Expiry: %llu\n", sess.expiry);
        printf("Status: %s\n", sess.status.c_str());
        printf("IP: %s\n", sess.ip.c_str());
        printf("----------------------------------------\n");
    }
}

static void PrintDetectionResults(const DetectionResult& result) {
    printf("Threat Assessment:\n");
    printf("----------------------------------------\n");
    printf("Threat Score: %d\n", result.threat_score);
    printf("Debugger: %s\n", result.debugger_detected ? "YES" : "NO");
    printf("VM Environment: %s\n", result.vm_detected ? "YES" : "NO");
    printf("Analysis Tools: %s\n", result.analysis_tools ? "YES" : "NO");
    printf("ntdll Hooks: %s\n", result.hooked_ntdll ? "YES" : "NO");
    
    if (!result.details.empty()) {
        printf("\nDetails:\n");
        for (const auto& detail : result.details) {
            printf("- %s\n", detail.c_str());
        }
    }
    printf("----------------------------------------\n");
}

// ── Main Loop ─────────────────────────────────────────────────────
int main() {
    // Check admin rights
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &AdministratorsGroup)) {
        if (CheckTokenMembership(nullptr, AdministratorsGroup, &isAdmin)) {
            if (!isAdmin) {
                printf("ERROR: This application requires administrator privileges.\n");
                printf("Please run as administrator.\n");
                FreeSid(AdministratorsGroup);
                system("pause");
                return 1;
            }
        }
        FreeSid(AdministratorsGroup);
    }
    
    // Configuration
    int autoRestartThreshold = 15; // Restart if threat score >= 15
    bool autoRestartEnabled = true;
    int scanInterval = 5000; // Scan every 5 seconds
    std::string targetIP = ""; // Empty = local restart
    
    std::vector<KeyAuthSession> sessions;
    DetectionResult lastResult;
    
    // Start session listener in background thread
    std::thread listenerThread(StartSessionListener);
    listenerThread.detach();
    
    while (true) {
        ClearScreen();
        PrintHeader();
        
        // Fetch sessions
        if (FetchKeyAuthSessions(sessions)) {
            PrintSessions(sessions);
        } else {
            printf("Failed to fetch sessions from KeyAuth\n");
        }
        
        printf("\n");
        
        // Perform detection
        DetectionResult result = PerformFullDetection();
        PrintDetectionResults(result);
        
        // Check for auto-restart
        if (autoRestartEnabled && result.threat_score >= autoRestartThreshold) {
            std::string reason = "High threat score (" + std::to_string(result.threat_score) + ")";
            RestartPC(reason, targetIP);
            break;
        }
        
        // Menu
        printf("\nOptions:\n");
        printf("1. Refresh sessions\n");
        printf("2. Force detection scan\n");
        printf("3. Toggle auto-restart (currently %s)\n", autoRestartEnabled ? "ON" : "OFF");
        printf("4. Change restart threshold (currently %d)\n", autoRestartThreshold);
        printf("5. Set target IP (currently: %s)\n", targetIP.empty() ? "LOCAL" : targetIP.c_str());
        printf("6. Force restart PC\n");
        printf("0. Exit\n");
        printf("Choice: ");
        
        int choice;
        scanf("%d", &choice);
        
        switch (choice) {
            case 1:
                // Refresh happens automatically at loop start
                break;
            case 2:
                // Force scan happens automatically at loop start
                break;
            case 3:
                autoRestartEnabled = !autoRestartEnabled;
                break;
            case 4: {
                printf("Enter new threshold: ");
                scanf("%d", &autoRestartThreshold);
                break;
            }
            case 5: {
                printf("Enter target IP (empty for local): ");
                char ip[64] = {};
                scanf("%63s", ip);
                targetIP = ip;
                break;
            }
            case 6:
                RestartPC("Manual restart", targetIP);
                break;
            case 0:
                return 0;
            default:
                break;
        }
    }
    
    return 0;
}
