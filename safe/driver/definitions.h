#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <windef.h>
#include <ntstrsafe.h>

#pragma comment(lib, "ntoskrnl.lib")

typedef struct _KPROCESS KPROCESS, *PKPROCESS;

#define EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET 0x2F8

typedef enum _SYSTEM_INFORMATION_CLASS_EX {
    SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS_EX;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    ULONG   Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    CHAR    FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct PiDDBCacheEntry {
    LIST_ENTRY      List;
    UNICODE_STRING  DriverName;
    ULONG           TimeDateStamp;
    NTSTATUS        LoadStatus;
    char            _pad[16];
} PIDCacheobj;

typedef struct _PEB_LDR_DATA_KM {
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  ModuleListLoadOrder;
    LIST_ENTRY  ModuleListMemoryOrder;
    LIST_ENTRY  ModuleListInitOrder;
} PEB_LDR_DATA_KM, *PPEB_LDR_DATA_KM;

typedef struct _LDR_DATA_TABLE_ENTRY_KM {
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_KM, *PLDR_DATA_TABLE_ENTRY_KM;

typedef struct _PEB_KM {
    UCHAR       Reserved1[2];
    UCHAR       BeingDebugged;
    UCHAR       Reserved2[1];
    PVOID       Reserved3[2];
    PPEB_LDR_DATA_KM Ldr;
} PEB_KM, *PPEB_KM;

extern "C" {

NTKERNELAPI PPEB_KM PsGetProcessPeb(IN PEPROCESS Process);

NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS   SourceProcess,
    PVOID       SourceAddress,
    PEPROCESS   TargetProcess,
    PVOID       TargetAddress,
    SIZE_T      BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T     ReturnSize
);

NTSTATUS NTAPI ZwProtectVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T ProtectSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

NTSYSAPI PVOID NTAPI RtlFindExportedRoutineByName(
    PVOID   ImageBase,
    PCCH    RoutineName
);

NTSTATUS ZwQuerySystemInformation(
    ULONG   InfoClass,
    PVOID   Buffer,
    ULONG   Length,
    PULONG  ReturnLength
);

}

static ULONG g_PoolTag = 'bFsN';

static __forceinline void InitPoolTag()
{
    LARGE_INTEGER perf = KeQueryPerformanceCounter(NULL);
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    ULONG64 seed = perf.QuadPart ^ time.QuadPart;
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    UCHAR tag[4];
    for (int i = 0; i < 4; i++) {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        tag[i] = (UCHAR)alphabet[seed % 52];
    }
    g_PoolTag = *(ULONG*)tag;
}

#define POOL_TAG g_PoolTag

extern POBJECT_TYPE* PsProcessType;
