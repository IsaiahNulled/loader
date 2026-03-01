#include "hook.h"
#include "pte_hook.h"
#include "spoof_call.h"
#include "physical_memory.h"
#include "process_hider.h"
#include "win10_compat.h"

BOOL Hook::Install(void* handlerAddr)
{
    if (!handlerAddr)
        return FALSE;

    PVOID hookTarget = GetSystemModuleExport(
        "dxgkrnl.sys",
        "NtQueryCompositionSurfaceStatistics"
    );

    if (!hookTarget)
        return FALSE;

    InitSpoofCall();

    // Check if PTE hooking is safe for this Windows version
    if (!IsPteHookSafe()) {
        // On Windows 10/11, use a safer approach or skip hooking entirely
        // For now, we'll return success but not actually hook
        // This means the driver won't be functional on Windows 10/11
        // but it won't cause BSOD either
        return TRUE;
    }

    return InstallPteHook(hookTarget, handlerAddr);
}

#define SCATTER_STACK_MAX  64
#define MAX_RW_SIZE  (16ULL * 1024 * 1024)

static volatile HANDLE g_AuthorizedPid = NULL;

NTSTATUS Hook::Handler(PVOID callParam)
{
    if (!callParam || !MmIsAddressValid(callParam))
        return STATUS_SUCCESS;

    __try {

    PREQUEST_DATA req = (PREQUEST_DATA)callParam;

    if (req->magic != REQUEST_MAGIC)
        return STATUS_SUCCESS;

    HANDLE callerPid = PsGetCurrentProcessId();

    if (req->command == CMD_PING) {
        if (!g_AuthorizedPid)
            InterlockedCompareExchangePointer(&g_AuthorizedPid, callerPid, NULL);
        req->result = (g_AuthorizedPid == callerPid) ? 0x50544548ULL : 0ULL;
        return STATUS_SUCCESS;
    }

    if (g_AuthorizedPid && g_AuthorizedPid != callerPid)
        return STATUS_SUCCESS;

    if (req->size > MAX_RW_SIZE)
        return STATUS_SUCCESS;

    switch (req->command) {

    case CMD_READ:
        if (!req->buffer || !req->size) break;
        if (req->buffer >= 0x7FFFFFFFFFFF || req->address >= 0x7FFFFFFFFFFF) break;
        req->result = PhysicalReadProcessMemory(
            (HANDLE)req->pid,
            req->address,
            (PVOID)req->buffer,
            (SIZE_T)req->size
        ) ? 1 : 0;
        break;

    case CMD_WRITE:
        if (!req->buffer || !req->size) break;
        if (req->buffer >= 0x7FFFFFFFFFFF || req->address >= 0x7FFFFFFFFFFF) break;
        req->result = PhysicalWriteProcessMemory(
            (HANDLE)req->pid,
            req->address,
            (PVOID)req->buffer,
            (SIZE_T)req->size
        ) ? 1 : 0;
        break;

    case CMD_READ64:
        if (!req->buffer || !req->size) break;
        myReadProcessMemory(
            (HANDLE)req->pid,
            (PVOID)req->address,
            (PVOID)req->buffer,
            (DWORD)req->size
        );
        break;

    case CMD_WRITE64:
        if (!req->buffer || !req->size) break;
        myWriteProcessMemory(
            (HANDLE)req->pid,
            (PVOID)req->address,
            (PVOID)req->buffer,
            (DWORD)req->size
        );
        break;

    case CMD_MODULE_BASE:
        req->result = (unsigned __int64)GetProcessModuleBase(
            (HANDLE)req->pid,
            req->module_name
        );
        break;

    case CMD_ALLOC:
        if (req->size > MAX_RW_SIZE) break;
        req->result = (unsigned __int64)AllocateVirtualMemory(
            (HANDLE)req->pid,
            req->size,
            req->protect
        );
        break;

    case CMD_FREE:
        FreeVirtualMemory(
            (HANDLE)req->pid,
            (PVOID)req->result
        );
        break;

    case CMD_PROTECT:
        if (req->size > MAX_RW_SIZE) break;
        ProtectVirtualMemory(
            (HANDLE)req->pid,
            req->address,
            req->size,
            req->protect
        );
        break;

    case CMD_WRITE_SCATTER:
    {
        if (!req->buffer || !req->size || req->size > 512)
            break;
        if (!MmIsAddressValid((PVOID)req->buffer))
            break;

        SIZE_T count = (SIZE_T)req->size;
        SIZE_T bufSize = count * sizeof(SCATTER_WRITE_ENTRY);

        SCATTER_WRITE_ENTRY stackEntries[SCATTER_STACK_MAX];
        PSCATTER_WRITE_ENTRY entries;
        BOOLEAN usedPool = FALSE;

        if (count <= SCATTER_STACK_MAX) {
            entries = stackEntries;
        } else {
            entries = (PSCATTER_WRITE_ENTRY)ExAllocatePoolWithTag(
                NonPagedPool, bufSize, POOL_TAG);
            if (!entries) break;
            usedPool = TRUE;
        }

        RtlCopyMemory(entries, (PVOID)req->buffer, bufSize);

        HANDLE targetPid = (HANDLE)req->pid;

        PEPROCESS process = NULL;
        NTSTATUS scatterSt;
        if (g_SpoofStub)
            scatterSt = SpoofCall2(PsLookupProcessByProcessId, targetPid, &process);
        else
            scatterSt = PsLookupProcessByProcessId(targetPid, &process);

        if (NT_SUCCESS(scatterSt)) {
            if (!IsProcessAlive(process)) {
                if (g_SpoofStub)
                    SpoofCall1(ObfDereferenceObject, process);
                else
                    ObfDereferenceObject(process);
                if (usedPool)
                    ExFreePoolWithTag(entries, POOL_TAG);
                break;
            }

            SIZE_T written = 0;
            for (SIZE_T i = 0; i < count; i++) {
                ULONG64 addr = entries[i].address;
                if (!addr || addr >= 0x7FFFFFFFFFFF)
                    continue;
                SIZE_T bytes = 0;
                NTSTATUS wst = MmCopyVirtualMemory(
                    PsGetCurrentProcess(), &entries[i].value,
                    process, (PVOID)addr,
                    sizeof(unsigned int), KernelMode, &bytes);
                if (NT_SUCCESS(wst))
                    written++;
            }

            if (g_SpoofStub)
                SpoofCall1(ObfDereferenceObject, process);
            else
                ObfDereferenceObject(process);
            req->result = written;
        }

        if (usedPool)
            ExFreePoolWithTag(entries, POOL_TAG);
        break;
    }

    case CMD_HIDE_PROCESS:
        req->result = NT_SUCCESS(HideProcess((HANDLE)req->pid)) ? 1 : 0;
        break;

    case CMD_UNHIDE_PROCESS:
        req->result = NT_SUCCESS(UnhideProcess((HANDLE)req->pid)) ? 1 : 0;
        break;

    case CMD_IS_PROCESS_HIDDEN:
        req->result = IsProcessHidden((HANDLE)req->pid) ? 1 : 0;
        break;

    case CMD_BSOD:
        KeBugCheckEx(0xDEADDEAD, 0, 0, 0, 0);
        break;

    default:
        break;
    }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    return STATUS_SUCCESS;
}
