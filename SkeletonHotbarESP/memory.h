#pragma once
// this is the main memory reading class. it handles opening the process, reading memory, and finding module bases. it's pretty straightforward, but I left comments to make it even easier to understand.

#include <windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <cstdio>
#include <string>

class MemoryReader {
private:
    HANDLE hProcess = nullptr;
    DWORD  pid = 0;
    bool   connected = false;

public:
    bool Init(DWORD processId) {
        pid = processId;
        hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            printf("[ERROR] OpenProcess failed for PID %u (error %u)\n", pid, GetLastError());
            return false;
        }
        connected = true;
        printf("[SUCCESS] Attached to process PID %u\n", pid);
        return true;
    }

    bool IsConnected() const { return connected; }
    DWORD GetPID() const { return pid; }

    bool ReadMemory(DWORD /*pid*/, uintptr_t address, void* buffer, size_t size) {
        if (!connected || !buffer || size == 0 || !address)
            return false;
        SIZE_T bytesRead = 0;
        BOOL ok = ReadProcessMemory(hProcess, (LPCVOID)address, buffer, size, &bytesRead);
        return ok && bytesRead == size;
    }

    template<typename T>
    T Read(DWORD pid, uintptr_t address) {
        T value{};
        ReadMemory(pid, address, &value, sizeof(T));
        return value;
    }

    uintptr_t GetModuleBase(DWORD targetPid, const wchar_t* moduleName) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPid);
        if (hSnap == INVALID_HANDLE_VALUE)
            return 0;

        MODULEENTRY32W me = {};
        me.dwSize = sizeof(me);
        uintptr_t base = 0;

        if (Module32FirstW(hSnap, &me)) {
            do {
                if (_wcsicmp(me.szModule, moduleName) == 0) {
                    base = (uintptr_t)me.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnap, &me));
        }
        CloseHandle(hSnap);
        return base;
    }

    void Cleanup() {
        if (hProcess) {
            CloseHandle(hProcess);
            hProcess = nullptr;
        }
        connected = false;
    }

    ~MemoryReader() { Cleanup(); }
};

// helper function to find process id by name, used for attachment. returns 0 if not found or on error.
inline DWORD FindProcessByName(const wchar_t* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    DWORD result = 0;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                result = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return result;
}
