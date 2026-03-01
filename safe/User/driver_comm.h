#pragma once
/*
 * driver_comm.h - Driver communication via hooked dxgkrnl function
 *
 * Uses NtQueryCompositionSurfaceStatistics (hooked in dxgkrnl.sys)
 * to send commands to the kernel driver.
 */

#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <mutex>
#include "shared.h"

// Ensure process hiding commands are available
#ifndef CMD_HIDE_PROCESS
#define CMD_HIDE_PROCESS 103
#define CMD_UNHIDE_PROCESS 104
#define CMD_IS_PROCESS_HIDDEN 105
#endif

/* ── NtQueryCompositionSurfaceStatistics ─────────────────────────── */

typedef NTSTATUS(NTAPI* fn_NtQueryCompositionSurfaceStatistics)(PVOID);

class DriverComm {
private:
    fn_NtQueryCompositionSurfaceStatistics pNtQuery = nullptr;
    bool connected = false;
    std::mutex m_drvMutex;  // Serialize ALL driver calls to prevent CR3 cache races

    bool SendRequest(REQUEST_DATA* req) {
        if (!pNtQuery) {
            printf("[ERROR] NtQuery function pointer is null\n");
            return false;
        }
        
        if (!req) {
            printf("[ERROR] Request pointer is null\n");
            return false;
        }
        
        req->magic = REQUEST_MAGIC;
        
        __try {
            pNtQuery(req);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

public:
    bool Init() {
        HMODULE hWin32u = LoadLibraryA("win32u.dll");
        if (!hWin32u) {
            printf("[ERROR] Failed to load win32u.dll\n");
            return false;
        }

        pNtQuery = (fn_NtQueryCompositionSurfaceStatistics)
            GetProcAddress(hWin32u, "NtQueryCompositionSurfaceStatistics");
        if (!pNtQuery) {
            printf("[ERROR] Failed to get NtQueryCompositionSurfaceStatistics address\n");
            return false;
        }

        /* Multiple ping attempts with different result checks */
        for (int i = 0; i < 3; i++) {
            REQUEST_DATA req = { 0 };
            req.command = CMD_PING;
            req.magic = REQUEST_MAGIC;
            
            if (SendRequest(&req)) {
                // Check for both possible ping responses
                if (req.result == 0x50544548 || req.result == 0x4B524E4C || req.result == 1) {
                    connected = true;
                    printf("[SUCCESS] Driver communication established (attempt %d)\n", i + 1);
                    return true;
                }
            }
            
            // Wait before retry
            Sleep(100);
        }

        printf("[ERROR] Driver ping failed - driver not loaded or hook not active\n");
        connected = false;
        return false;
    }

    bool IsConnected() const { return connected; }

    bool ReadMemory(DWORD pid, uintptr_t address, void* buffer, size_t size) {
        if (!connected || !buffer || size == 0)
            return false;
        
        std::lock_guard<std::mutex> lock(m_drvMutex);
        REQUEST_DATA req = { 0 };
        req.command = CMD_READ;
        req.pid = pid;
        req.address = address;
        req.buffer = (unsigned __int64)buffer;
        req.size = size;
        
        return SendRequest(&req) && req.result;
    }

    bool WriteMemory(DWORD pid, uintptr_t address, void* buffer, size_t size) {
        if (!connected || !buffer || size == 0)
            return false;
        
        std::lock_guard<std::mutex> lock(m_drvMutex);
        REQUEST_DATA req = { 0 };
        req.command = CMD_WRITE;
        req.pid = pid;
        req.address = address;
        req.buffer = (unsigned __int64)buffer;
        req.size = size;
        
        return SendRequest(&req) && req.result;
    }

    uintptr_t GetModuleBase(DWORD pid, const wchar_t* moduleName) {
        std::lock_guard<std::mutex> lock(m_drvMutex);
        REQUEST_DATA req = { 0 };
        req.command = CMD_MODULE_BASE;
        req.pid = pid;
        wcsncpy_s(req.module_name, 64, moduleName, _TRUNCATE);
        SendRequest(&req);
        return (uintptr_t)req.result;
    }

    uintptr_t AllocMemory(DWORD pid, size_t size, DWORD protect) {
        std::lock_guard<std::mutex> lock(m_drvMutex);
        REQUEST_DATA req = { 0 };
        req.command = CMD_ALLOC;
        req.pid = pid;
        req.size = size;
        req.protect = protect;
        SendRequest(&req);
        return (uintptr_t)req.result;
    }

    void FreeMemory(DWORD pid, uintptr_t address) {
        std::lock_guard<std::mutex> lock(m_drvMutex);
        REQUEST_DATA req = { 0 };
        req.command = CMD_FREE;
        req.pid = pid;
        req.result = address;
        SendRequest(&req);
    }

    void ProtectMemory(DWORD pid, uintptr_t address, size_t size, DWORD protect) {
        std::lock_guard<std::mutex> lock(m_drvMutex);
        REQUEST_DATA req = { 0 };
        req.command = CMD_PROTECT;
        req.pid = pid;
        req.address = address;
        req.size = size;
        req.protect = protect;
        SendRequest(&req);
    }

    /* ── Driver Status and Diagnostics ───────────────────────────────── */

    bool CheckDriverStatus() {
        if (!connected) {
            printf("[STATUS] Driver not connected\n");
            return false;
        }
        
        std::lock_guard<std::mutex> lock(m_drvMutex);
        REQUEST_DATA req = { 0 };
        req.command = CMD_PING;
        req.magic = REQUEST_MAGIC;
        
        if (SendRequest(&req)) {
            printf("[STATUS] Driver ping response: 0x%llx\n", req.result);
            return (req.result == 0x50544548 || req.result == 0x4B524E4C || req.result == 1);
        }
        
        printf("[STATUS] Driver ping failed\n");
        return false;
    }

    void Reconnect() {
        printf("[INFO] Attempting to reconnect to driver...\n");
        connected = false;
        Init();
    }

    /* ── Scatter Write (batched 4-byte writes, 1 attach/detach) ──── */

    bool WriteScatter(DWORD pid, SCATTER_WRITE_ENTRY* entries, size_t count) {
        if (!connected || !entries || count == 0 || count > 512)
            return false;

        std::lock_guard<std::mutex> lock(m_drvMutex);
        REQUEST_DATA req = { 0 };
        req.command = CMD_WRITE_SCATTER;
        req.pid = pid;
        req.buffer = (unsigned __int64)entries;
        req.size = count;

        return SendRequest(&req) && req.result > 0;
    }

    /* ── Process Hiding Functions ───────────────────────────────── */

    bool HideProcess(DWORD pid) {
        if (!connected) {
            printf("[ERROR] Driver not connected - cannot hide process\n");
            return false;
        }
        
        std::lock_guard<std::mutex> lock(m_drvMutex);
        REQUEST_DATA req = { 0 };
        req.command = CMD_HIDE_PROCESS;
        req.pid = pid;
        
        bool result = SendRequest(&req) && req.result;
        if (result) {
            printf("[SUCCESS] Process hidden (PID: %d)\n", pid);
        } else {
            printf("[ERROR] Failed to hide process (PID: %d)\n", pid);
        }
        return result;
    }

    bool UnhideProcess(DWORD pid) {
        if (!connected) {
            printf("[ERROR] Driver not connected - cannot unhide process\n");
            return false;
        }
        
        std::lock_guard<std::mutex> lock(m_drvMutex);
        REQUEST_DATA req = { 0 };
        req.command = CMD_UNHIDE_PROCESS;
        req.pid = pid;
        
        bool result = SendRequest(&req) && req.result;
        if (result) {
            printf("[SUCCESS] Process unhidden (PID: %d)\n", pid);
        } else {
            printf("[ERROR] Failed to unhide process (PID: %d)\n", pid);
        }
        return result;
    }

    bool IsProcessHidden(DWORD pid) {
        if (!connected) {
            printf("[ERROR] Driver not connected - cannot check process visibility\n");
            return false;
        }
        
        std::lock_guard<std::mutex> lock(m_drvMutex);
        REQUEST_DATA req = { 0 };
        req.command = CMD_IS_PROCESS_HIDDEN;
        req.pid = pid;
        
        if (SendRequest(&req)) {
            return req.result != 0;
        }
        
        return false;
    }

    /* ── Write capability test ─────────────────────────────────── */

    bool TestWriteCapability(DWORD pid, uintptr_t testAddr) {
        if (!connected || !testAddr) return false;

        // Read original value
        float original = 0;
        if (!ReadMemory(pid, testAddr, &original, sizeof(float))) {
            printf("[WRITE-TEST] FAIL: cannot read test address 0x%llx\n", (unsigned long long)testAddr);
            return false;
        }

        // Write same value back
        if (!WriteMemory(pid, testAddr, &original, sizeof(float))) {
            printf("[WRITE-TEST] FAIL: WriteMemory returned false for 0x%llx\n", (unsigned long long)testAddr);
            printf("[WRITE-TEST] >>> Driver does NOT support writes (safe driver loaded?)\n");
            return false;
        }

        // Read back to verify
        float readback = 0;
        ReadMemory(pid, testAddr, &readback, sizeof(float));
        if (readback == original) {
            printf("[WRITE-TEST] OK: write capability confirmed (addr=0x%llx val=%.2f)\n",
                   (unsigned long long)testAddr, original);
            return true;
        } else {
            printf("[WRITE-TEST] WARN: write returned success but readback mismatch (%.2f != %.2f)\n",
                   readback, original);
            return false;
        }
    }

    /* ── Templated helpers ───────────────────────────────────────── */

    template<typename T>
    T Read(DWORD pid, uintptr_t address) {
        T value{};
        ReadMemory(pid, address, &value, sizeof(T));
        return value;
    }

    template<typename T>
    bool Write(DWORD pid, uintptr_t address, const T& value) {
        return WriteMemory(pid, address, (void*)&value, sizeof(T));
    }
};
