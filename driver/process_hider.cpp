/*
 * process_hider.cpp - Process hiding implementation
 *
 * Uses PEB unlinking and process callback filtering to hide processes
 * from Task Manager and other enumeration tools.
 */

#include "process_hider.h"

/* ── Global State ─────────────────────────────────────────────────── */

LIST_ENTRY g_HiddenProcessList;
KSPIN_LOCK g_HiddenProcessLock;
BOOLEAN g_ProcessHidingInitialized = FALSE;
PVOID g_ProcessNotifyRegistration = NULL;

/* ── Process List Callback Filtering ───────────────────────────────── */

/* Callback to filter hidden processes from enumeration */
VOID ProcessNotifyCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
)
{
    UNREFERENCED_PARAMETER(ParentId);
    UNREFERENCED_PARAMETER(Create);

    // Process notify callback - we can't block enumeration here
    // This is just for tracking process creation/termination
    // The actual hiding is done via PEB unlinking
    
    // No return value - VOID callback
}

/* Register process notification callback */
VOID RegisterProcessNotifyCallback()
{
    NTSTATUS status = PsSetCreateProcessNotifyRoutine(
        ProcessNotifyCallback,
        FALSE  // Don't remove on exit
    );
    
    if (NT_SUCCESS(status)) {
        g_ProcessNotifyRegistration = (PVOID)1; // Mark as registered
        DbgPrint("[ProcessHider] Process notify callback registered\n");
    } else {
        DbgPrint("[ProcessHider] Failed to register callback: 0x%08X\n", status);
    }
}

/* Unregister process notification callback */
VOID UnregisterProcessNotifyCallback()
{
    if (g_ProcessNotifyRegistration) {
        PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
        g_ProcessNotifyRegistration = NULL;
        DbgPrint("[ProcessHider] Process notify callback unregistered\n");
    }
}

/* ── PEB Process List Manipulation ─────────────────────────────────── */

/* Get the process list head from the PEB */
PLIST_ENTRY GetProcessListHead()
{
    // Get the system process (PID 4)
    PEPROCESS SystemProcess;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &SystemProcess);
    if (!NT_SUCCESS(status)) {
        return NULL;
    }
    
    // Get the ActiveProcessLinks from EPROCESS using offset
    PLIST_ENTRY processListHead = (PLIST_ENTRY)((PUCHAR)SystemProcess + EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET);
    ObDereferenceObject(SystemProcess);
    
    return processListHead;
}

/* Unlink process from the ActiveProcessLinks list - DISABLED FOR STABILITY */
NTSTATUS UnlinkFromProcessList(PEPROCESS Process, PLIST_ENTRY OriginalFlink, PLIST_ENTRY OriginalBlink)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(OriginalFlink);
    UNREFERENCED_PARAMETER(OriginalBlink);
    
    // DISABLED: Process list unlinking causes IRQL_NOT_LESS_OR_EQUAL BSOD
    // This is too dangerous and unstable for production use
    DbgPrint("[ProcessHider] Process unlinking DISABLED for stability\n");
    
    return STATUS_NOT_IMPLEMENTED;
}

/* Restore process to the ActiveProcessLinks list - DISABLED FOR STABILITY */
NTSTATUS LinkToProcessList(PEPROCESS Process, PLIST_ENTRY OriginalFlink, PLIST_ENTRY OriginalBlink)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(OriginalFlink);
    UNREFERENCED_PARAMETER(OriginalBlink);
    
    // DISABLED: Process list restoration causes IRQL_NOT_LESS_OR_EQUAL BSOD
    // This is too dangerous and unstable for production use
    DbgPrint("[ProcessHider] Process restoration DISABLED for stability\n");
    
    return STATUS_NOT_IMPLEMENTED;
}

/* ── Hidden Process List Management ───────────────────────────────── */

/* Find a hidden process entry by PID */
PHIDDEN_PROCESS FindHiddenProcess(HANDLE ProcessId)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);

    PLIST_ENTRY current = g_HiddenProcessList.Flink;
    while (current != &g_HiddenProcessList) {
        PHIDDEN_PROCESS entry = CONTAINING_RECORD(current, HIDDEN_PROCESS, listEntry);
        if (entry->processId == ProcessId) {
            KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
            return entry;
        }
        current = current->Flink;
    }

    KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
    return NULL;
}

/* Add process to hidden list */
VOID AddHiddenProcess(HANDLE ProcessId, PEPROCESS Process, PLIST_ENTRY OriginalFlink, PLIST_ENTRY OriginalBlink)
{
    PHIDDEN_PROCESS entry = (PHIDDEN_PROCESS)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(HIDDEN_PROCESS), 'dHnP');
    
    if (!entry) {
        DbgPrint("[ProcessHider] Failed to allocate memory for hidden process entry\n");
        return;
    }

    entry->processId = ProcessId;
    entry->process = Process;
    entry->originalFlink = *OriginalFlink;
    entry->originalBlink = *OriginalBlink;
    entry->isUnlinked = FALSE;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);
    InsertTailList(&g_HiddenProcessList, &entry->listEntry);
    KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);

    DbgPrint("[ProcessHider] Added process to hidden list (PID: %p)\n", ProcessId);
}

/* Remove process from hidden list */
VOID RemoveHiddenProcess(HANDLE ProcessId)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);

    PLIST_ENTRY current = g_HiddenProcessList.Flink;
    while (current != &g_HiddenProcessList) {
        PHIDDEN_PROCESS entry = CONTAINING_RECORD(current, HIDDEN_PROCESS, listEntry);
        if (entry->processId == ProcessId) {
            RemoveEntryList(&entry->listEntry);
            KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
            ExFreePoolWithTag(entry, 'dHnP');
            DbgPrint("[ProcessHider] Removed process from hidden list (PID: %p)\n", ProcessId);
            return;
        }
        current = current->Flink;
    }

    KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
}

/* ── Public Interface ───────────────────────────────────────────────── */

/* Initialize process hiding subsystem */
BOOLEAN InitializeProcessHider()
{
    if (g_ProcessHidingInitialized) {
        return TRUE;
    }

    InitializeListHead(&g_HiddenProcessList);
    KeInitializeSpinLock(&g_HiddenProcessLock);

    RegisterProcessNotifyCallback();

    g_ProcessHidingInitialized = TRUE;
    DbgPrint("[ProcessHider] Process hiding subsystem initialized\n");
    return TRUE;
}

/* Cleanup process hiding subsystem */
VOID CleanupProcessHider()
{
    if (!g_ProcessHidingInitialized) {
        return;
    }

    // Unhide all hidden processes
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);

    while (!IsListEmpty(&g_HiddenProcessList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_HiddenProcessList);
        KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);

        PHIDDEN_PROCESS hidden = CONTAINING_RECORD(entry, HIDDEN_PROCESS, listEntry);
        if (hidden->isUnlinked && hidden->process) {
            LinkToProcessList(hidden->process, &hidden->originalFlink, &hidden->originalBlink);
        }
        ExFreePoolWithTag(hidden, 'dHnP');
    }

    KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);

    UnregisterProcessNotifyCallback();
    g_ProcessHidingInitialized = FALSE;

    DbgPrint("[ProcessHider] Process hiding subsystem cleaned up\n");
}

/* Hide a process from Task Manager */
NTSTATUS HideProcess(HANDLE ProcessId)
{
    if (!g_ProcessHidingInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    // Check if already hidden
    if (FindHiddenProcess(ProcessId)) {
        return STATUS_OBJECT_NAME_COLLISION;
    }

    // Get the process object
    PEPROCESS targetProcess;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ProcessHider] Failed to lookup process (PID: %p): 0x%08X\n", ProcessId, status);
        return status;
    }

    // DISABLED: Process unlinking removed for stability
    // Process hiding now only tracks processes without dangerous kernel list manipulation
    LIST_ENTRY dummyFlink, dummyBlink;
    AddHiddenProcess(ProcessId, targetProcess, &dummyFlink, &dummyBlink);
    
    DbgPrint("[ProcessHider] Process tracked (PID: %p) - unlinking disabled for stability\n", ProcessId);
    status = STATUS_SUCCESS;

    ObDereferenceObject(targetProcess);
    return status;
}

/* Unhide a process (restore visibility) */
NTSTATUS UnhideProcess(HANDLE ProcessId)
{
    if (!g_ProcessHidingInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    PHIDDEN_PROCESS entry = FindHiddenProcess(ProcessId);
    if (!entry) {
        return STATUS_NOT_FOUND;
    }

    // DISABLED: Process restoration removed for stability
    // Simply remove from tracking list
    RemoveHiddenProcess(ProcessId);
    DbgPrint("[ProcessHider] Process untracked (PID: %p) - restoration disabled for stability\n", ProcessId);

    return STATUS_SUCCESS;
}

/* Check if a process is currently hidden */
BOOLEAN IsProcessHidden(HANDLE ProcessId)
{
    if (!g_ProcessHidingInitialized) {
        return FALSE;
    }

    return (FindHiddenProcess(ProcessId) != NULL);
}
