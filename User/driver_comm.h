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
#include "shared.h"

/* ── NtQueryCompositionSurfaceStatistics ─────────────────────────── */

typedef NTSTATUS(NTAPI* fn_NtQueryCompositionSurfaceStatistics)(PVOID);

class DriverComm {
private:
    fn_NtQueryCompositionSurfaceStatistics pNtQuery = nullptr;
    bool connected = false;

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
            // Add some debugging for specific commands
            if (req->command == CMD_PING) {
                // For ping, we want to see what happens
                pNtQuery(req);
            } else {
                // For other commands, use exception handling
                pNtQuery(req);
            }
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("[ERROR] Exception in driver communication (command: %d)\n", req->command);
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
        if (!connected) {
            printf("[ERROR] Driver not connected - cannot read memory\n");
            return false;
        }
        
        if (!buffer || size == 0) {
            printf("[ERROR] Invalid buffer or size for ReadMemory\n");
            return false;
        }
        
        REQUEST_DATA req = { 0 };
        req.command = CMD_READ;
        req.pid = pid;
        req.address = address;
        req.buffer = (unsigned __int64)buffer;
        req.size = size;
        
        bool result = SendRequest(&req) && req.result;
        if (!result) {
            printf("[ERROR] ReadMemory failed - pid: %d, addr: 0x%llx, size: %zu\n", pid, address, size);
        }
        return result;
    }

    bool WriteMemory(DWORD pid, uintptr_t address, void* buffer, size_t size) {
        if (!connected) {
            printf("[ERROR] Driver not connected - cannot write memory\n");
            return false;
        }
        
        if (!buffer || size == 0) {
            printf("[ERROR] Invalid buffer or size for WriteMemory\n");
            return false;
        }
        
        REQUEST_DATA req = { 0 };
        req.command = CMD_WRITE;
        req.pid = pid;
        req.address = address;
        req.buffer = (unsigned __int64)buffer;
        req.size = size;
        
        bool result = SendRequest(&req) && req.result;
        if (!result) {
            printf("[ERROR] WriteMemory failed - pid: %d, addr: 0x%llx, size: %zu\n", pid, address, size);
        }
        return result;
    }

    uintptr_t GetModuleBase(DWORD pid, const wchar_t* moduleName) {
        REQUEST_DATA req = { 0 };
        req.command = CMD_MODULE_BASE;
        req.pid = pid;
        wcsncpy_s(req.module_name, 64, moduleName, _TRUNCATE);
        SendRequest(&req);
        return (uintptr_t)req.result;
    }

    uintptr_t AllocMemory(DWORD pid, size_t size, DWORD protect) {
        REQUEST_DATA req = { 0 };
        req.command = CMD_ALLOC;
        req.pid = pid;
        req.size = size;
        req.protect = protect;
        SendRequest(&req);
        return (uintptr_t)req.result;
    }

    void FreeMemory(DWORD pid, uintptr_t address) {
        REQUEST_DATA req = { 0 };
        req.command = CMD_FREE;
        req.pid = pid;
        req.result = address;
        SendRequest(&req);
    }

    void ProtectMemory(DWORD pid, uintptr_t address, size_t size, DWORD protect) {
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

        REQUEST_DATA req = { 0 };
        req.command = CMD_WRITE_SCATTER;
        req.pid = pid;
        req.buffer = (unsigned __int64)entries;
        req.size = count;

        return SendRequest(&req) && req.result > 0;
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
