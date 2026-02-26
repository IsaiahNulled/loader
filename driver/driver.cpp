/*
 * driver.cpp - Driver entry point
 *
 * Loaded by kdmapper. On entry:
 *   1. Clean all traces (PiDDB, MmUnloadedDrivers)
 *   2. Install dxgkrnl.sys hook for communication
 *   3. Hide driver object completely
 *
 * After this, the driver is invisible to all standard
 * enumeration tools and BattlEye scanning.
 */

#include "driver.h"
#include "hook.h"
#include "cleaner.h"
#include "spoofer.h"

volatile BOOLEAN g_SpoofActive = FALSE;

/* ── Real Entry (called after DriverEntry) ───────────────────────── */

static NTSTATUS RealEntry(PDRIVER_OBJECT DriverObject)
{
    /* 1. HWID spoof — must run FIRST at PASSIVE_LEVEL before anything queries serials */
    if (InitSpoofer())
        g_SpoofActive = TRUE;

    /* 2. Install dxgkrnl hook */
    if (!Hook::Install(&Hook::Handler)) {
        CleanupSpoofer();
        return STATUS_UNSUCCESSFUL;
    }

    /* 3. Clean all traces and hide driver */
    CleanAllTraces(DriverObject);

    /* Driver is now:
     *   - Hidden from PsLoadedModuleList
     *   - PiDDB entry for iqvw64e.sys removed
     *   - MmUnloadedDrivers entry cleaned
     *   - PE headers erased
     *   - DriverObject fields NULLed
     *   - Communication via hooked dxgkrnl function
     */

    return STATUS_SUCCESS;
}

/* ── DriverEntry ─────────────────────────────────────────────────── */

extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    return RealEntry(DriverObject);
}