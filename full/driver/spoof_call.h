#pragma once
#include "definitions.h"

static PVOID g_SpoofGadget = NULL;

static BOOLEAN FindSpoofGadget()
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
        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        if (section->Misc.VirtualSize < 5)
            continue;

        PUCHAR start = (PUCHAR)ntBase + section->VirtualAddress;
        ULONG  size  = section->Misc.VirtualSize;

        if (section->VirtualAddress + size > ntSize)
            size = ntSize - section->VirtualAddress;

        for (ULONG j = 0; j + 5 <= size; j++) {
            if (start[j]     == 0x48 &&
                start[j + 1] == 0x83 &&
                start[j + 2] == 0xC4 &&
                start[j + 3] == 0x28 &&
                start[j + 4] == 0xC3)
            {
                g_SpoofGadget = &start[j];
                return TRUE;
            }
        }
    }

    return FALSE;
}

#pragma pack(push, 1)
typedef struct _SPOOF_STUB {
    UCHAR code[52];
} SPOOF_STUB;
#pragma pack(pop)

static UCHAR g_SpoofCode[52] = {
    0x41, 0x5B,
    0x48, 0x8B, 0xC1,
    0x48, 0x8B, 0xCA,
    0x49, 0x8B, 0xD0,
    0x4D, 0x8B, 0xC1,
    0x4C, 0x8B, 0x4C, 0x24, 0x20,
    0x48, 0x83, 0xEC, 0x38,
    0x49, 0xBA,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x89, 0x14, 0x24,
    0x4C, 0x89, 0x5C, 0x24, 0x30,
    0xFF, 0xE0
};

static PVOID g_SpoofStub = NULL;

static BOOLEAN InitSpoofStub()
{
    if (!g_SpoofGadget)
        return FALSE;

    g_SpoofStub = ExAllocatePoolWithTag(NonPagedPoolExecute, sizeof(g_SpoofCode), POOL_TAG);
    if (!g_SpoofStub)
        return FALSE;

    RtlCopyMemory(g_SpoofStub, g_SpoofCode, sizeof(g_SpoofCode));
    *(PVOID*)((PUCHAR)g_SpoofStub + 25) = g_SpoofGadget;

    return TRUE;
}

typedef NTSTATUS (*fn_spoof_1)(PVOID target, PVOID a1);
#define SpoofCall1(fn, a1) \
    ((fn_spoof_1)g_SpoofStub)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1))

typedef NTSTATUS (*fn_spoof_2)(PVOID target, PVOID a1, PVOID a2);
#define SpoofCall2(fn, a1, a2) \
    ((fn_spoof_2)g_SpoofStub)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1), (PVOID)(ULONG_PTR)(a2))

typedef NTSTATUS (*fn_spoof_3)(PVOID target, PVOID a1, PVOID a2, PVOID a3);
#define SpoofCall3(fn, a1, a2, a3) \
    ((fn_spoof_3)g_SpoofStub)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1), \
     (PVOID)(ULONG_PTR)(a2), (PVOID)(ULONG_PTR)(a3))

typedef NTSTATUS (*fn_spoof_4)(PVOID target, PVOID a1, PVOID a2, PVOID a3, PVOID a4);
#define SpoofCall4(fn, a1, a2, a3, a4) \
    ((fn_spoof_4)g_SpoofStub)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1), \
     (PVOID)(ULONG_PTR)(a2), (PVOID)(ULONG_PTR)(a3), (PVOID)(ULONG_PTR)(a4))

static BOOLEAN InitSpoofCall()
{
    if (!FindSpoofGadget())
        return FALSE;
    return InitSpoofStub();
}

static VOID CleanupSpoofCall()
{
    if (g_SpoofStub) {
        ExFreePoolWithTag(g_SpoofStub, POOL_TAG);
        g_SpoofStub = NULL;
    }
}
