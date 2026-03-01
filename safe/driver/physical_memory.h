#pragma once
#include "definitions.h"
#include "memory.h"
#include "spoof_call.h"
#include <intrin.h>

#define PTE_PRESENT      0x1ULL
#define PTE_LARGE_PAGE   0x80ULL
#define PTE_PHYS_MASK    0x0000FFFFFFFFF000ULL
#define PAGE_OFFSET_MASK 0xFFFULL

typedef struct _CR3_CACHE_ENTRY {
    volatile ULONG64 cr3;
    volatile HANDLE  pid;
    volatile ULONG   callCount;
    volatile ULONG   revalidateCount;
    volatile BOOLEAN validated;
    volatile LONG    lock;
} CR3_CACHE_ENTRY;

static CR3_CACHE_ENTRY g_Cr3Cache = { 0, 0, 0, 0, FALSE, 0 };

#define CR3_CACHE_THRESHOLD  500
#define CR3_REVALIDATE_INTERVAL  50000

static __forceinline BOOLEAN Cr3CacheTryLock()
{
    return (InterlockedCompareExchange(&g_Cr3Cache.lock, 1, 0) == 0);
}

static __forceinline void Cr3CacheUnlock()
{
    InterlockedExchange(&g_Cr3Cache.lock, 0);
}

static BOOLEAN ValidateCR3(ULONG64 cr3)
{
    if (cr3 == 0 || (cr3 & 0xFFF) != 0)
        return FALSE;

    ULONG64 pml4e = 0;
    MM_COPY_ADDRESS addr;
    addr.PhysicalAddress.QuadPart = (LONGLONG)(cr3 & PTE_PHYS_MASK);
    SIZE_T bytesRead = 0;

    NTSTATUS status = MmCopyMemory(&pml4e, addr, sizeof(pml4e),
        MM_COPY_MEMORY_PHYSICAL, &bytesRead);

    if (!NT_SUCCESS(status) || bytesRead != sizeof(pml4e))
        return FALSE;

    return (pml4e & PTE_PRESENT) != 0;
}

static ULONG64 GetProcessCR3(HANDLE pid)
{
    if (!pid) return 0;

    HANDLE  cachedPid   = g_Cr3Cache.pid;
    BOOLEAN cachedValid = g_Cr3Cache.validated;
    ULONG64 cachedCr3   = g_Cr3Cache.cr3;

    if (cachedPid == pid && cachedValid && cachedCr3)
        return cachedCr3;

    BOOLEAN gotLock = Cr3CacheTryLock();

    if (gotLock) {
        if (g_Cr3Cache.pid != pid) {
            g_Cr3Cache.pid = pid;
            g_Cr3Cache.callCount = 0;
            g_Cr3Cache.cr3 = 0;
            g_Cr3Cache.validated = FALSE;
        }
        g_Cr3Cache.callCount++;
    }

    PEPROCESS process = NULL;
    NTSTATUS lookupStatus;
    if (g_SpoofStub)
        lookupStatus = SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        lookupStatus = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(lookupStatus)) {
        if (gotLock) Cr3CacheUnlock();
        return 0;
    }

    if (!IsProcessAlive(process)) {
        if (g_SpoofStub)
            SpoofCall1(ObfDereferenceObject, process);
        else
            ObfDereferenceObject(process);
        if (gotLock) Cr3CacheUnlock();
        return 0;
    }

    KAPC_STATE apc;
    if (g_SpoofStub)
        SpoofCall2(KeStackAttachProcess, process, &apc);
    else
        KeStackAttachProcess(process, &apc);

    ULONG64 cr3 = __readcr3();

    if (g_SpoofStub)
        SpoofCall1(KeUnstackDetachProcess, &apc);
    else
        KeUnstackDetachProcess(&apc);

    if (g_SpoofStub)
        SpoofCall1(ObfDereferenceObject, process);
    else
        ObfDereferenceObject(process);

    if (gotLock) {
        if (cr3 && ValidateCR3(cr3)) {
            g_Cr3Cache.cr3 = cr3;
            if (g_Cr3Cache.callCount >= CR3_CACHE_THRESHOLD)
                g_Cr3Cache.validated = TRUE;
        }
        Cr3CacheUnlock();
    }

    return cr3;
}

static void MaybeRevalidateCR3(HANDLE pid)
{
    if (!g_Cr3Cache.validated || g_Cr3Cache.pid != pid)
        return;

    ULONG count = (ULONG)InterlockedIncrement((volatile LONG*)&g_Cr3Cache.revalidateCount);
    if (count < CR3_REVALIDATE_INTERVAL)
        return;

    if (!Cr3CacheTryLock())
        return;

    if (g_Cr3Cache.revalidateCount < CR3_REVALIDATE_INTERVAL) {
        Cr3CacheUnlock();
        return;
    }

    g_Cr3Cache.revalidateCount = 0;
    Cr3CacheUnlock();

    PEPROCESS process = NULL;
    NTSTATUS st;
    if (g_SpoofStub)
        st = SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        st = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(st)) return;

    if (!IsProcessAlive(process)) {
        if (g_SpoofStub)
            SpoofCall1(ObfDereferenceObject, process);
        else
            ObfDereferenceObject(process);
        return;
    }

    KAPC_STATE apc;
    if (g_SpoofStub)
        SpoofCall2(KeStackAttachProcess, process, &apc);
    else
        KeStackAttachProcess(process, &apc);

    ULONG64 newCr3 = __readcr3();

    if (g_SpoofStub)
        SpoofCall1(KeUnstackDetachProcess, &apc);
    else
        KeUnstackDetachProcess(&apc);

    if (g_SpoofStub)
        SpoofCall1(ObfDereferenceObject, process);
    else
        ObfDereferenceObject(process);

    if (newCr3 && ValidateCR3(newCr3)) {
        if (Cr3CacheTryLock()) {
            g_Cr3Cache.cr3 = newCr3;
            Cr3CacheUnlock();
        }
    }
}

#define MAX_PHYSICAL_ADDRESS  0x0001000000000000ULL

static NTSTATUS ReadPhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size)
{
    if (!buffer || !size || !physAddr)
        return STATUS_INVALID_PARAMETER;

    if (physAddr >= MAX_PHYSICAL_ADDRESS)
        return STATUS_INVALID_ADDRESS;

    MM_COPY_ADDRESS addr;
    addr.PhysicalAddress.QuadPart = (LONGLONG)physAddr;
    SIZE_T bytesRead = 0;

    NTSTATUS status;
    __try {
        status = MmCopyMemory(buffer, addr, size,
            MM_COPY_MEMORY_PHYSICAL, &bytesRead);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

static NTSTATUS WritePhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size)
{
    if (!buffer || !size || !physAddr)
        return STATUS_INVALID_PARAMETER;

    if (physAddr >= MAX_PHYSICAL_ADDRESS)
        return STATUS_INVALID_ADDRESS;

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)physAddr;

    /* MmCached is required for regular process RAM.
       MmNonCached bypasses CPU cache coherency and can cause
       machine check exceptions (BSOD) on regular memory. */
    PVOID mapped = MmMapIoSpace(pa, size, MmCached);
    if (!mapped)
        return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        RtlCopyMemory(mapped, buffer, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        MmUnmapIoSpace(mapped, size);
        return GetExceptionCode();
    }

    MmUnmapIoSpace(mapped, size);
    return STATUS_SUCCESS;
}

static ULONG64 TranslateVirtualAddress(ULONG64 cr3, ULONG64 virtualAddress)
{
    if (!cr3 || !virtualAddress)
        return 0;

    ULONG64 pml4_idx = (virtualAddress >> 39) & 0x1FF;
    ULONG64 pdpt_idx = (virtualAddress >> 30) & 0x1FF;
    ULONG64 pd_idx   = (virtualAddress >> 21) & 0x1FF;
    ULONG64 pt_idx   = (virtualAddress >> 12) & 0x1FF;
    ULONG64 offset   = virtualAddress & PAGE_OFFSET_MASK;

    ULONG64 pte = 0;

    if (!NT_SUCCESS(ReadPhysicalAddress(
            (cr3 & PTE_PHYS_MASK) + pml4_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;

    if (!NT_SUCCESS(ReadPhysicalAddress(
            (pte & PTE_PHYS_MASK) + pdpt_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;
    if (pte & PTE_LARGE_PAGE)
        return (pte & 0xFFFFC0000000ULL) + (virtualAddress & 0x3FFFFFFFULL);

    if (!NT_SUCCESS(ReadPhysicalAddress(
            (pte & PTE_PHYS_MASK) + pd_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;
    if (pte & PTE_LARGE_PAGE)
        return (pte & 0xFFFFFE00000ULL) + (virtualAddress & 0x1FFFFFULL);

    if (!NT_SUCCESS(ReadPhysicalAddress(
            (pte & PTE_PHYS_MASK) + pt_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;

    return (pte & PTE_PHYS_MASK) + offset;
}

#define READ_STACK_BUF  256

static BOOL PhysicalReadProcessMemory(
    HANDLE pid, ULONG64 virtualAddress, PVOID userBuffer, SIZE_T size)
{
    if (!userBuffer || !size || !virtualAddress)
        return FALSE;

    if ((ULONG64)userBuffer >= 0x7FFFFFFFFFFF || virtualAddress >= 0x7FFFFFFFFFFF)
        return FALSE;

    ULONG64 cr3 = GetProcessCR3(pid);
    if (!cr3) return FALSE;

    UCHAR stackBuf[READ_STACK_BUF];
    PUCHAR kernelBuf;
    BOOLEAN usedPool = FALSE;

    if (size <= READ_STACK_BUF) {
        kernelBuf = stackBuf;
    } else {
        kernelBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG);
        if (!kernelBuf) return FALSE;
        usedPool = TRUE;
    }

    RtlZeroMemory(kernelBuf, size);

    MaybeRevalidateCR3(pid);

    BOOL success = TRUE;
    SIZE_T totalRead = 0;

    __try {
        while (totalRead < size)
        {
            ULONG64 currentVA = virtualAddress + totalRead;
            SIZE_T pageRemaining = 0x1000 - (currentVA & PAGE_OFFSET_MASK);
            SIZE_T chunkSize = min(pageRemaining, size - totalRead);

            ULONG64 physAddr = TranslateVirtualAddress(cr3, currentVA);
            if (!physAddr) {
                success = FALSE;
                break;
            }

            if (!NT_SUCCESS(ReadPhysicalAddress(physAddr, kernelBuf + totalRead, chunkSize))) {
                success = FALSE;
                break;
            }

            totalRead += chunkSize;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_Cr3Cache.validated = FALSE;
        g_Cr3Cache.cr3 = 0;
        success = FALSE;
    }

    if (success) {
        __try {
            RtlCopyMemory(userBuffer, kernelBuf, size);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            success = FALSE;
        }
    }

    if (usedPool)
        ExFreePoolWithTag(kernelBuf, POOL_TAG);
    return success;
}

#define WRITE_STACK_BUF  256

static BOOL PhysicalWriteProcessMemory(
    HANDLE pid, ULONG64 virtualAddress, PVOID userBuffer, SIZE_T size)
{
    if (!userBuffer || !size || !virtualAddress)
        return FALSE;

    if ((ULONG64)userBuffer >= 0x7FFFFFFFFFFF || virtualAddress >= 0x7FFFFFFFFFFF)
        return FALSE;

    ULONG64 cr3 = GetProcessCR3(pid);
    if (!cr3) return FALSE;

    UCHAR stackBuf[WRITE_STACK_BUF];
    PUCHAR kernelBuf;
    BOOLEAN usedPool = FALSE;

    if (size <= WRITE_STACK_BUF) {
        kernelBuf = stackBuf;
    } else {
        kernelBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG);
        if (!kernelBuf) return FALSE;
        usedPool = TRUE;
    }

    /* Copy user data into kernel buffer first */
    RtlCopyMemory(kernelBuf, userBuffer, size);

    MaybeRevalidateCR3(pid);

    BOOL success = TRUE;
    SIZE_T totalWritten = 0;

    __try {
        while (totalWritten < size)
        {
            ULONG64 currentVA = virtualAddress + totalWritten;
            SIZE_T pageRemaining = 0x1000 - (currentVA & PAGE_OFFSET_MASK);
            SIZE_T chunkSize = min(pageRemaining, size - totalWritten);

            ULONG64 physAddr = TranslateVirtualAddress(cr3, currentVA);
            if (!physAddr) {
                success = FALSE;
                break;
            }

            if (!NT_SUCCESS(WritePhysicalAddress(physAddr, kernelBuf + totalWritten, chunkSize))) {
                success = FALSE;
                break;
            }

            totalWritten += chunkSize;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_Cr3Cache.validated = FALSE;
        g_Cr3Cache.cr3 = 0;
        success = FALSE;
    }

    if (usedPool)
        ExFreePoolWithTag(kernelBuf, POOL_TAG);
    return success;
}
