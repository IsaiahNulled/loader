#pragma once
#include "definitions.h"
#include <intrin.h>

// Windows 10 compatibility functions
static BOOLEAN UseEnhancedSafety() {
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    
    if (NT_SUCCESS(RtlGetVersion(&versionInfo))) {
        // Windows 10 1903+ (build 18362+) has stricter memory protection
        if (versionInfo.dwMajorVersion == 10 && versionInfo.dwBuildNumber >= 18362) {
            return TRUE;
        }
        
        // Windows 11 definitely needs enhanced safety
        if (versionInfo.dwMajorVersion >= 10 && versionInfo.dwBuildNumber >= 22000) {
            return TRUE;
        }
    }
    
    return FALSE;
}

static BOOLEAN UseSafeFlushing() {
    return UseEnhancedSafety();
}

static BOOLEAN AvoidLargePageManipulation() {
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    
    if (NT_SUCCESS(RtlGetVersion(&versionInfo))) {
        // Windows 10 2004+ (build 19041) has issues with large page splitting
        if (versionInfo.dwMajorVersion == 10 && versionInfo.dwBuildNumber >= 19041) {
            return TRUE;
        }
    }
    
    return FALSE;
}

extern "C" NTKERNELAPI ULONG_PTR KeIpiGenericCall(
    PKIPI_BROADCAST_WORKER BroadcastFunction, ULONG_PTR Context);

static ULONG_PTR FlushEntireTlbIpi(ULONG_PTR) {
    __writecr3(__readcr3());
    return 0;
}
static ULONG_PTR FlushSinglePageIpi(ULONG_PTR pageAddr) {
    __invlpg((PVOID)pageAddr);
    return 0;
}

static BOOLEAN g_PteHookInstalled = FALSE;

typedef union _PTE_ENTRY {
    ULONG64 value;
    struct {
        ULONG64 Present        : 1;
        ULONG64 ReadWrite      : 1;
        ULONG64 UserSupervisor : 1;
        ULONG64 WriteThrough   : 1;
        ULONG64 CacheDisable   : 1;
        ULONG64 Accessed       : 1;
        ULONG64 Dirty          : 1;
        ULONG64 LargePage      : 1;
        ULONG64 Global         : 1;
        ULONG64 CopyOnWrite    : 1;
        ULONG64 Prototype      : 1;
        ULONG64 Reserved0      : 1;
        ULONG64 PageFrameNumber: 36;
        ULONG64 Reserved1      : 4;
        ULONG64 SoftwareWsIndex: 11;
        ULONG64 NoExecute      : 1;
    };
} PTE_ENTRY, *PPTE_ENTRY;

typedef struct _PTE_HOOK_STATE {
    PVOID       targetVA;
    PPTE_ENTRY  pteAddress;
    ULONG64     originalPfn;
    ULONG64     newPfn;
    PVOID       newPageVA;
    PHYSICAL_ADDRESS newPagePA;
    BOOLEAN     active;
} PTE_HOOK_STATE;

static PTE_HOOK_STATE g_PteHook = { 0 };

typedef PVOID (__fastcall *fn_MiGetPteAddress)(PVOID va);
static fn_MiGetPteAddress pMiGetPteAddress = NULL;

static BOOLEAN FindMiGetPteAddress()
{
    ULONG bytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bytes);
    if (!bytes) return FALSE;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)
        ExAllocatePoolWithTag(NonPagedPool, bytes, POOL_TAG);
    if (!modules) return FALSE;

    if (!NT_SUCCESS(ZwQuerySystemInformation(
            SystemModuleInformation, modules, bytes, &bytes))) {
        ExFreePoolWithTag(modules, POOL_TAG);
        return FALSE;
    }

    PVOID ntBase = modules->Modules[0].ImageBase;
    ExFreePoolWithTag(modules, POOL_TAG);
    if (!ntBase) return FALSE;

    PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(ntBase);
    if (!ntHeaders) return FALSE;
    ULONG ntSize = ntHeaders->OptionalHeader.SizeOfImage;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->Misc.VirtualSize == 0)
            continue;

        PUCHAR start = (PUCHAR)ntBase + section->VirtualAddress;
        ULONG  size  = section->Misc.VirtualSize;

        if (section->VirtualAddress + size > ntSize)
            size = ntSize - section->VirtualAddress;
        if (size < 31) continue;

        for (ULONG j = 0; j + 31 <= size; j++) {
            if (start[j + 0]  == 0x48 &&
                start[j + 1]  == 0xC1 &&
                start[j + 2]  == 0xE9 &&
                start[j + 3]  == 0x09 &&
                start[j + 4]  == 0x48 &&
                start[j + 5]  == 0xB8 &&
                start[j + 14] == 0x48 &&
                start[j + 15] == 0x23 &&
                start[j + 16] == 0xC8 &&
                start[j + 17] == 0x48 &&
                start[j + 18] == 0xB8 &&
                start[j + 27] == 0x48 &&
                start[j + 28] == 0x03 &&
                start[j + 29] == 0xC1 &&
                start[j + 30] == 0xC3)
            {
                pMiGetPteAddress = (fn_MiGetPteAddress)(&start[j]);
                return TRUE;
            }
        }
    }

    return FALSE;
}

static PPTE_ENTRY GetPte(PVOID va)
{
    if (!pMiGetPteAddress) return NULL;
    return (PPTE_ENTRY)pMiGetPteAddress(va);
}

static PPTE_ENTRY GetPde(PVOID va)
{
    if (!pMiGetPteAddress) return NULL;
    return (PPTE_ENTRY)pMiGetPteAddress(pMiGetPteAddress(va));
}

static BOOLEAN InstallPteHook(PVOID targetFunction, PVOID handlerAddr)
{
    if (!targetFunction || !handlerAddr)
        return FALSE;

    if (!pMiGetPteAddress && !FindMiGetPteAddress())
        return FALSE;

    ULONG64 targetVA = (ULONG64)targetFunction;
    ULONG64 pageBase = targetVA & ~0xFFFULL;
    ULONG   pageOffset = (ULONG)(targetVA & 0xFFF);

    PPTE_ENTRY pde = GetPde((PVOID)pageBase);
    if (!pde || !MmIsAddressValid(pde))
        return FALSE;

    PTE_ENTRY pdeEntry;
    pdeEntry.value = pde->value;
    if (!pdeEntry.Present)
        return FALSE;

    // Windows 10 safety: Avoid large page manipulation on newer builds
    if (pdeEntry.LargePage && AvoidLargePageManipulation()) {
        // On problematic Windows 10 builds, skip large page splitting
        // Fall back to direct PTE hooking (may not work but won't BSOD)
        goto try_direct_pte;
    }

    if (pdeEntry.LargePage) {
        PHYSICAL_ADDRESS low, high, boundary;
        low.QuadPart = 0;
        high.QuadPart = 0xFFFFFFFFFFFFULL;
        boundary.QuadPart = 0;

        PVOID ptPage = MmAllocateContiguousMemorySpecifyCache(
            PAGE_SIZE, low, high, boundary, MmCached);
        if (!ptPage) return FALSE;

        PHYSICAL_ADDRESS ptPagePA = MmGetPhysicalAddress(ptPage);
        PPTE_ENTRY newPtEntries = (PPTE_ENTRY)ptPage;
        ULONG64 largePfn = pdeEntry.PageFrameNumber;

        for (int i = 0; i < 512; i++) {
            PTE_ENTRY pte;
            pte.value = 0;
            pte.Present = 1;
            pte.ReadWrite = pdeEntry.ReadWrite;
            pte.UserSupervisor = pdeEntry.UserSupervisor;
            pte.WriteThrough = pdeEntry.WriteThrough;
            pte.CacheDisable = pdeEntry.CacheDisable;
            pte.Accessed = 1;
            pte.Dirty = pdeEntry.Dirty;
            pte.Global = pdeEntry.Global;
            pte.NoExecute = pdeEntry.NoExecute;
            pte.PageFrameNumber = largePfn + i;
            newPtEntries[i] = pte;
        }

        KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

        PTE_ENTRY newPde;
        newPde.value = pdeEntry.value;
        newPde.LargePage = 0;
        newPde.PageFrameNumber = ptPagePA.QuadPart >> 12;

        InterlockedExchange64((volatile LONG64*)&pde->value, newPde.value);

        KeLowerIrql(oldIrql);

        // Windows 10 safety: Use safer flushing on newer builds
        if (UseSafeFlushing()) {
            // Use single CPU flush instead of IPI broadcast on Windows 10
            __writecr3(__readcr3());
        } else {
            KeIpiGenericCall(FlushEntireTlbIpi, 0);
        }
    }

try_direct_pte:
    PPTE_ENTRY pte = GetPte((PVOID)pageBase);
    if (!pte || !MmIsAddressValid(pte))
        return FALSE;

    PTE_ENTRY originalPte;
    originalPte.value = pte->value;
    if (!originalPte.Present)
        return FALSE;

    PHYSICAL_ADDRESS low, high, boundary;
    low.QuadPart = 0;
    high.QuadPart = 0xFFFFFFFFFFFFULL;
    boundary.QuadPart = 0;

    PVOID newPage = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, low, high, boundary, MmCached);
    if (!newPage) return FALSE;

    PHYSICAL_ADDRESS newPagePA = MmGetPhysicalAddress(newPage);
    ULONG64 newPfn = newPagePA.QuadPart >> 12;

    PHYSICAL_ADDRESS origPA;
    origPA.QuadPart = (LONGLONG)originalPte.PageFrameNumber << 12;

    PVOID origMapped = MmMapIoSpace(origPA, PAGE_SIZE, MmCached);
    if (!origMapped) {
        MmFreeContiguousMemory(newPage);
        return FALSE;
    }

    if (g_PteHookInstalled) {
        MmFreeContiguousMemory(newPage);
        MmUnmapIoSpace(origMapped, PAGE_SIZE);
        return TRUE;
    }

    RtlCopyMemory(newPage, origMapped, PAGE_SIZE);
    MmUnmapIoSpace(origMapped, PAGE_SIZE);

    PUCHAR hookSite = (PUCHAR)newPage + pageOffset;
    hookSite[0] = 0x48;
    hookSite[1] = 0xB8;
    uintptr_t addr = (uintptr_t)handlerAddr;
    RtlCopyMemory(&hookSite[2], &addr, sizeof(void*));
    hookSite[10] = 0xFF;
    hookSite[11] = 0xE0;

    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

    PTE_ENTRY newPte;
    newPte.value = originalPte.value;
    newPte.PageFrameNumber = newPfn;

    InterlockedExchange64((volatile LONG64*)&pte->value, newPte.value);

    KeLowerIrql(oldIrql);

    // Windows 10 safety: Use safer flushing on newer builds
    if (UseSafeFlushing()) {
        // Use INVLPG instead of IPI on Windows 10 to avoid BSOD
        __invlpg((PVOID)pageBase);
    } else {
        KeIpiGenericCall(FlushSinglePageIpi, pageBase);
    }

    g_PteHook.targetVA    = targetFunction;
    g_PteHook.pteAddress  = pte;
    g_PteHook.originalPfn = originalPte.PageFrameNumber;
    g_PteHook.newPfn      = newPfn;
    g_PteHook.newPageVA   = newPage;
    g_PteHook.newPagePA   = newPagePA;
    g_PteHook.active      = TRUE;
    g_PteHookInstalled    = TRUE;

    return TRUE;
}

static VOID RestorePteHook()
{
    if (!g_PteHook.active || !g_PteHook.pteAddress)
        return;

    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

    PTE_ENTRY restored;
    restored.value = g_PteHook.pteAddress->value;
    restored.PageFrameNumber = g_PteHook.originalPfn;

    InterlockedExchange64(
        (volatile LONG64*)&g_PteHook.pteAddress->value,
        restored.value);

    KeLowerIrql(oldIrql);

    ULONG64 pageBase = (ULONG64)g_PteHook.targetVA & ~0xFFFULL;
    KeIpiGenericCall(FlushSinglePageIpi, pageBase);

    if (g_PteHook.newPageVA)
        MmFreeContiguousMemory(g_PteHook.newPageVA);

    g_PteHook.active = FALSE;
}
