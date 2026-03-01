#pragma once
#include "definitions.h"

PVOID GetSystemModuleBase(const char* moduleName);
PVOID GetSystemModuleExport(const char* moduleName, LPCSTR routineName);
BOOL WriteReadOnlyMemory(void* address, void* buffer, size_t size);
BOOL WriteMemory(void* address, void* buffer, size_t size);
BOOL myReadProcessMemory(HANDLE pid, PVOID address, PVOID buffer, DWORD size);
BOOL myWriteProcessMemory(HANDLE pid, PVOID address, PVOID buffer, DWORD size);
PVOID AllocateVirtualMemory(HANDLE pid, ULONGLONG size, DWORD protect);
VOID  FreeVirtualMemory(HANDLE pid, PVOID base);
BOOL  ProtectVirtualMemory(HANDLE pid, UINT_PTR base, ULONGLONG size, DWORD protection);
BOOLEAN IsProcessAlive(PEPROCESS process);
PVOID GetProcessHandle(HANDLE pid);
PVOID GetProcessModuleBase(HANDLE pid, const wchar_t* moduleName);