#include <ntifs.h>
#include <ntddk.h>
#include "include\spoofer.h"
#include "include\definitions.h"

/* Global spoofer active flag */
volatile BOOLEAN g_SpoofActive = FALSE;

/* Driver entry point */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    /* Initialize the HWID spoofer */
    if (InitSpoofer()) {
        g_SpoofActive = TRUE;
        DbgPrint("[HWIDSpoofer] Initialized successfully\n");
        return STATUS_SUCCESS;
    }

    DbgPrint("[HWIDSpoofer] Failed to initialize\n");
    return STATUS_UNSUCCESSFUL;
}

/* Driver unload routine */
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    /* Cleanup spoofer hooks */
    CleanupSpoofer();
    g_SpoofActive = FALSE;
    DbgPrint("[HWIDSpoofer] Unloaded\n");
}
