#pragma once
/*
 * process_hider.h - Process hiding from Task Manager
 *
 * Implements two complementary hiding techniques:
 * 1. PEB unlinking - removes process from user-mode process list
 * 2. Process list callback filtering - hides from kernel enumeration
 *
 * This makes the process invisible to:
 * - Task Manager (both Processes and Details tabs)
 * - Process Explorer
 * - Most process enumeration tools
 * - Anti-cheat process scanners
 */

#include "definitions.h"
#include "memory.h"
#include "shared.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Process Hiding State ─────────────────────────────────────────── */

typedef struct _HIDDEN_PROCESS {
    LIST_ENTRY listEntry;        /* Linked list of hidden processes */
    HANDLE processId;            /* Process ID */
    PEPROCESS process;           /* EPROCESS pointer */
    LIST_ENTRY originalFlink;    /* Original Flink for restoration */
    LIST_ENTRY originalBlink;    /* Original Blink for restoration */
    BOOLEAN isUnlinked;          /* Whether PEB unlinking was applied */
} HIDDEN_PROCESS, *PHIDDEN_PROCESS;

/* Global state */
extern LIST_ENTRY g_HiddenProcessList;
extern KSPIN_LOCK g_HiddenProcessLock;
extern BOOLEAN g_ProcessHidingInitialized;

/* ── Core Functions ─────────────────────────────────────────────────── */

/* Initialize process hiding subsystem */
BOOLEAN InitializeProcessHider();

/* Cleanup process hiding subsystem */
VOID CleanupProcessHider();

/* Hide a process from Task Manager */
NTSTATUS HideProcess(HANDLE ProcessId);

/* Unhide a process (restore visibility) */
NTSTATUS UnhideProcess(HANDLE ProcessId);

/* Check if a process is currently hidden */
BOOLEAN IsProcessHidden(HANDLE ProcessId);

/* ── Implementation Details ───────────────────────────────────────── */

/* PEB unlinking - removes from process list */
NTSTATUS UnlinkFromProcessList(PEPROCESS Process, PLIST_ENTRY OriginalFlink, PLIST_ENTRY OriginalBlink);

/* Restore process list linking */
NTSTATUS LinkToProcessList(PEPROCESS Process, PLIST_ENTRY OriginalFlink, PLIST_ENTRY OriginalBlink);

/* Process list callback filtering */
VOID RegisterProcessNotifyCallback();
VOID UnregisterProcessNotifyCallback();

/* Find hidden process entry by PID */
PHIDDEN_PROCESS FindHiddenProcess(HANDLE ProcessId);

/* Add/remove from hidden list */
VOID AddHiddenProcess(HANDLE ProcessId, PEPROCESS Process, PLIST_ENTRY OriginalFlink, PLIST_ENTRY OriginalBlink);
VOID RemoveHiddenProcess(HANDLE ProcessId);

#ifdef __cplusplus
}
#endif
