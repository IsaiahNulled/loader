#pragma once
#include "definitions.h"
#include "kcrypt.h"
#include <intrin.h>

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

        KeIpiGenericCall(FlushEntireTlbIpi, 0);
    }

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

    // ── Obfuscated trampoline (17 bytes) ──────────────────────
    // Instead of the easily-detected  mov rax, addr; jmp rax  (FF E0)
    // pattern, we use:  push rax; mov rax, ~addr; not rax;
    //                   xchg [rsp], rax; ret
    // The handler address is stored bitwise-inverted in the binary.
    PUCHAR hookSite = (PUCHAR)newPage + pageOffset;
    uintptr_t encodedAddr = ~(uintptr_t)handlerAddr;
    hookSite[0]  = 0x50;                                     // push rax
    hookSite[1]  = 0x48; hookSite[2] = 0xB8;                 // mov rax, imm64
    RtlCopyMemory(&hookSite[3], &encodedAddr, 8);             //   (~handler)
    hookSite[11] = 0x48; hookSite[12] = 0xF7; hookSite[13] = 0xD0; // not rax
    hookSite[14] = 0x48; hookSite[15] = 0x87; hookSite[16] = 0x04; // xchg [rsp], rax
    hookSite[17] = 0x24;
    hookSite[18] = 0xC3;                                     // ret

    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

    PTE_ENTRY newPte;
    newPte.value = originalPte.value;
    newPte.PageFrameNumber = newPfn;

    InterlockedExchange64((volatile LONG64*)&pte->value, newPte.value);

    KeLowerIrql(oldIrql);

    KeIpiGenericCall(FlushSinglePageIpi, pageBase);

    // Encrypt sensitive hook state with runtime key
    g_PteHook.targetVA    = (PVOID)kc::EncryptU64((ULONG64)targetFunction);
    g_PteHook.pteAddress  = (PPTE_ENTRY)kc::EncryptPtr((PVOID)pte);
    g_PteHook.originalPfn = kc::EncryptU64(originalPte.PageFrameNumber);
    g_PteHook.newPfn      = kc::EncryptU64(newPfn);
    g_PteHook.newPageVA   = kc::EncryptPtr(newPage);
    g_PteHook.newPagePA   = newPagePA;  // PA needed for free
    g_PteHook.active      = TRUE;
    g_PteHookInstalled    = TRUE;

    return TRUE;
}

static VOID RestorePteHook()
{
    if (!g_PteHook.active)
        return;

    // Decrypt hook state
    PPTE_ENTRY pte = (PPTE_ENTRY)kc::DecryptPtr((PVOID)g_PteHook.pteAddress);
    ULONG64 origPfn = kc::DecryptU64(g_PteHook.originalPfn);
    PVOID targetVA = (PVOID)kc::DecryptU64((ULONG64)g_PteHook.targetVA);
    PVOID pageVA = kc::DecryptPtr(g_PteHook.newPageVA);

    if (!pte) return;

    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

    PTE_ENTRY restored;
    restored.value = pte->value;
    restored.PageFrameNumber = origPfn;

    InterlockedExchange64(
        (volatile LONG64*)&pte->value,
        restored.value);

    KeLowerIrql(oldIrql);

    ULONG64 pageBase = (ULONG64)targetVA & ~0xFFFULL;
    KeIpiGenericCall(FlushSinglePageIpi, pageBase);

    if (pageVA)
        MmFreeContiguousMemory(pageVA);

    g_PteHook.active = FALSE;
}
