#pragma once
#include "definitions.h"

static PVOID  g_KernelBase = NULL;
static ULONG  g_KernelSize = 0;

static PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
    ULONG_PTR Instr = (ULONG_PTR)Instruction;
    LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
    return (PVOID)(Instr + InstructionSize + RipOffset);
}

static NTSTATUS PatternScan(
    const UCHAR* pattern, UCHAR wildcard, ULONG_PTR len,
    const void* base, ULONG_PTR size, PVOID* ppFound)
{
    if (!ppFound || !pattern || !base) return STATUS_INVALID_PARAMETER;

    for (ULONG_PTR i = 0; i < size - len; i++) {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < len; j++) {
            if (pattern[j] != wildcard && pattern[j] != ((const UCHAR*)base)[i + j]) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

static PVOID GetKernelBase(PULONG pSize)
{
    if (g_KernelBase) {
        if (pSize) *pSize = g_KernelSize;
        return g_KernelBase;
    }

    UNICODE_STRING routineName;
    RtlUnicodeStringInit(&routineName, L"NtOpenFile");
    PVOID checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (!checkPtr) return NULL;

    ULONG bytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0) return NULL;

    PRTL_PROCESS_MODULES pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool, bytes, POOL_TAG);
    if (!pMods) return NULL;
    RtlZeroMemory(pMods, bytes);

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);
    if (NT_SUCCESS(status)) {
        for (ULONG i = 0; i < pMods->NumberOfModules; i++) {
            if (checkPtr >= pMods->Modules[i].ImageBase &&
                checkPtr < (PVOID)((PUCHAR)pMods->Modules[i].ImageBase + pMods->Modules[i].ImageSize))
            {
                g_KernelBase = pMods->Modules[i].ImageBase;
                g_KernelSize = pMods->Modules[i].ImageSize;
                if (pSize) *pSize = g_KernelSize;
                break;
            }
        }
    }
    ExFreePoolWithTag(pMods, POOL_TAG);
    return g_KernelBase;
}

static NTSTATUS ScanSection(
    const char* section, const UCHAR* pattern, UCHAR wildcard,
    ULONG_PTR len, PVOID* ppFound)
{
    if (!ppFound) return STATUS_INVALID_PARAMETER;

    PVOID base = GetKernelBase(NULL);
    if (!base) return STATUS_NOT_FOUND;

    PIMAGE_NT_HEADERS64 pHdr = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(base);
    if (!pHdr) return STATUS_INVALID_IMAGE_FORMAT;

    PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
    for (PIMAGE_SECTION_HEADER pSec = pFirstSection;
         pSec < pFirstSection + pHdr->FileHeader.NumberOfSections; pSec++)
    {
        ANSI_STRING s1, s2;
        RtlInitAnsiString(&s1, section);
        RtlInitAnsiString(&s2, (PCCHAR)pSec->Name);
        if (RtlCompareString(&s1, &s2, TRUE) == 0) {
            PVOID ptr = NULL;
            NTSTATUS st = PatternScan(pattern, wildcard, len,
                (PUCHAR)base + pSec->VirtualAddress, pSec->Misc.VirtualSize, &ptr);
            if (NT_SUCCESS(st))
                *(PULONG_PTR)ppFound = (ULONG_PTR)ptr - (ULONG_PTR)base;
            return st;
        }
    }
    return STATUS_NOT_FOUND;
}

static VOID HideDriverObject(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject) return;

    if (DriverObject->DriverName.Buffer) {
        RtlZeroMemory(DriverObject->DriverName.Buffer,
            DriverObject->DriverName.MaximumLength);
        DriverObject->DriverName.Length = 0;
    }

    if (DriverObject->DriverSection) {
        PLIST_ENTRY entry = (PLIST_ENTRY)DriverObject->DriverSection;
        PLIST_ENTRY prev = entry->Blink;
        PLIST_ENTRY next = entry->Flink;
        if (prev && next) {
            prev->Flink = next;
            next->Blink = prev;
            entry->Flink = entry;
            entry->Blink = entry;
        }
    }

    __try {
        if (DriverObject->DriverStart) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)DriverObject->DriverStart;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(
                    (UCHAR*)DriverObject->DriverStart + dos->e_lfanew);
                ULONG headerSize = nt->OptionalHeader.SizeOfHeaders;
                if (headerSize == 0 || headerSize > PAGE_SIZE)
                    headerSize = PAGE_SIZE;
                RtlZeroMemory(DriverObject->DriverStart, headerSize);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    DriverObject->DriverSection = NULL;
    DriverObject->DriverInit = NULL;
    DriverObject->DriverStart = NULL;
    DriverObject->DriverSize = 0;

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = NULL;
    }
}

static BOOLEAN CleanAllTraces(PDRIVER_OBJECT DriverObject)
{
    HideDriverObject(DriverObject);

    return TRUE;
}
