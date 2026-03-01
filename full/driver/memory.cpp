#include "definitions.h"
#include "memory.h"

BOOLEAN IsProcessAlive(PEPROCESS process)
{
    if (!process) return FALSE;
    LARGE_INTEGER timeout;
    timeout.QuadPart = 0;
    return (KeWaitForSingleObject(process, Executive, KernelMode, FALSE, &timeout) == STATUS_TIMEOUT);
}

PVOID GetSystemModuleBase(const char* moduleName)
{
    ULONG bytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bytes);
    if (!bytes) return NULL;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool, bytes, POOL_TAG);
    if (!modules) return NULL;

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation,
        modules, bytes, &bytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, POOL_TAG);
        return NULL;
    }

    PVOID base = NULL;
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        char* name = (char*)modules->Modules[i].FullPathName +
                     modules->Modules[i].OffsetToFileName;
        if (_stricmp(name, moduleName) == 0) {
            base = modules->Modules[i].ImageBase;
            break;
        }
    }

    ExFreePoolWithTag(modules, POOL_TAG);
    return base;
}

PVOID GetSystemModuleExport(const char* moduleName, LPCSTR routineName)
{
    PVOID base = GetSystemModuleBase(moduleName);
    if (!base) return NULL;
    return RtlFindExportedRoutineByName(base, routineName);
}

BOOL WriteReadOnlyMemory(void* address, void* buffer, size_t size)
{
    if (!address || !buffer || !size) return FALSE;

    PMDL mdl = IoAllocateMdl(address, (ULONG)size, FALSE, FALSE, NULL);
    if (!mdl) return FALSE;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return FALSE;
    }

    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return FALSE;
    }

    NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    if (NT_SUCCESS(status)) {
        memcpy(mapped, buffer, size);
    }

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    return NT_SUCCESS(status);
}

BOOL WriteMemory(void* address, void* buffer, size_t size)
{
    if (!address || !buffer) return FALSE;

    __try {
        RtlCopyMemory(address, buffer, size);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

BOOL myReadProcessMemory(HANDLE pid, PVOID address, PVOID buffer, DWORD size)
{
    if (!address || !buffer || !size) return FALSE;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) return FALSE;

    if (!IsProcessAlive(process)) {
        ObfDereferenceObject(process);
        return FALSE;
    }

    __try {
        if (address > (PVOID)0x7FFFFFFFFFFF) {
            ObfDereferenceObject(process);
            return FALSE;
        }

        SIZE_T bytes = 0;
        status = MmCopyVirtualMemory(
            process, address,
            PsGetCurrentProcess(), buffer,
            (SIZE_T)size, KernelMode, &bytes
        );

        ObfDereferenceObject(process);
        return NT_SUCCESS(status) && bytes == size;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ObfDereferenceObject(process);
        return FALSE;
    }
}

BOOL myWriteProcessMemory(HANDLE pid, PVOID address, PVOID buffer, DWORD size)
{
    if (!address || !buffer || !size) return FALSE;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) return FALSE;

    if (!IsProcessAlive(process)) {
        ObfDereferenceObject(process);
        return FALSE;
    }

    __try {
        if (address > (PVOID)0x7FFFFFFFFFFF) {
            ObfDereferenceObject(process);
            return FALSE;
        }

        SIZE_T bytes = 0;
        status = MmCopyVirtualMemory(
            PsGetCurrentProcess(), buffer,
            process, address,
            (SIZE_T)size, KernelMode, &bytes
        );

        ObfDereferenceObject(process);
        return NT_SUCCESS(status) && bytes == size;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ObfDereferenceObject(process);
        return FALSE;
    }
}

PVOID AllocateVirtualMemory(HANDLE pid, ULONGLONG size, DWORD protect)
{
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return NULL;
    }

    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return NULL;

    if (!IsProcessAlive(process)) {
        ObfDereferenceObject(process);
        return NULL;
    }

    __try {
        KAPC_STATE apc;
        KeStackAttachProcess(process, &apc);

        PVOID base = NULL;
        SIZE_T regionSize = (SIZE_T)size;
        NTSTATUS status = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &base, 0, &regionSize,
            MEM_COMMIT | MEM_RESERVE, protect);

        KeUnstackDetachProcess(&apc);
        ObfDereferenceObject(process);

        return NT_SUCCESS(status) ? base : NULL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ObfDereferenceObject(process);
        return NULL;
    }
}

VOID FreeVirtualMemory(HANDLE pid, PVOID base)
{
    if (!base) return;

    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return;

    if (!IsProcessAlive(process)) {
        ObfDereferenceObject(process);
        return;
    }

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    SIZE_T regionSize = 0;
    ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &regionSize, MEM_RELEASE);

    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);
}

BOOL ProtectVirtualMemory(HANDLE pid, UINT_PTR base, ULONGLONG size, DWORD protection)
{
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return FALSE;

    if (!IsProcessAlive(process)) {
        ObfDereferenceObject(process);
        return FALSE;
    }

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    PVOID addr = (PVOID)base;
    SIZE_T regionSize = (SIZE_T)size;
    ULONG oldProtect = 0;
    NTSTATUS status = ZwProtectVirtualMemory(
        ZwCurrentProcess(), &addr, &regionSize, protection, &oldProtect);

    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);

    return NT_SUCCESS(status);
}

PVOID GetProcessHandle(HANDLE pid)
{
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return NULL;

    HANDLE hProcess = NULL;
    NTSTATUS status = ObOpenObjectByPointer(
        process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_ALL_ACCESS, *PsProcessType,
        KernelMode, &hProcess);

    ObfDereferenceObject(process);
    return NT_SUCCESS(status) ? (PVOID)hProcess : NULL;
}

PVOID GetProcessModuleBase(HANDLE pid, const wchar_t* moduleName)
{
    if (!moduleName) return NULL;

    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return NULL;

    if (!IsProcessAlive(process)) {
        ObfDereferenceObject(process);
        return NULL;
    }

    WCHAR nameBuffer[64] = { 0 };
    __try {
        wcsncpy(nameBuffer, moduleName, 63);
        nameBuffer[63] = L'\0';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ObfDereferenceObject(process);
        return NULL;
    }

    PVOID result = NULL;

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    __try {
        PPEB_KM peb = PsGetProcessPeb(process);
        if (peb && peb->Ldr) {
            for (PLIST_ENTRY pEntry = peb->Ldr->ModuleListLoadOrder.Flink;
                 pEntry != &peb->Ldr->ModuleListLoadOrder;
                 pEntry = pEntry->Flink)
            {
                PLDR_DATA_TABLE_ENTRY_KM entry = CONTAINING_RECORD(
                    pEntry, LDR_DATA_TABLE_ENTRY_KM, InLoadOrderModuleList);

                if (entry->BaseDllName.Buffer) {
                    if (_wcsicmp(entry->BaseDllName.Buffer, nameBuffer) == 0) {
                        result = entry->DllBase;
                        break;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = NULL;
    }

    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);

    return result;
}
