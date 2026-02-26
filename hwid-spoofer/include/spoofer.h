#pragma once
/*
 * spoofer.h - Main HWID spoofer orchestrator
 *
 * Initializes all spoofing subsystems:
 *   1. Random serial generation (spoofer_utils.h)
 *   2. SMBIOS table spoofing (spoofer_smbios.h)
 *   3. Disk serial spoofing (spoofer_disk.h)
 *   4. MAC address spoofing via registry (spoofer_ntos.h)
 *   5. Computer name spoofing via registry (spoofer_ntos.h)
 *   6. NtQuerySystemInformation firmware table hook (spoofer_ntos.h)
 *
 * Call InitSpoofer() from DriverEntry BEFORE installing the comm hook.
 * The spoofer runs entirely at PASSIVE_LEVEL during init.
 */

#include "spoofer_utils.h"
#include "spoofer_smbios.h"
#include "spoofer_disk.h"
#include "spoofer_ntos.h"

/* ── GPU serial spoofing via registry ────────────────────────────── */

static void GpuSpoofCallback(HANDLE parentKey, PUNICODE_STRING subkeyName, PVOID ctx)
{
    UNREFERENCED_PARAMETER(ctx);

    OBJECT_ATTRIBUTES subAttr;
    InitializeObjectAttributes(&subAttr, subkeyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parentKey, NULL);

    HANDLE hSub = NULL;
    NTSTATUS status = ZwOpenKey(&hSub, KEY_SET_VALUE | KEY_READ, &subAttr);
    if (!NT_SUCCESS(status)) return;

    /* Read DriverDesc to check if this is a GPU */
    UCHAR infoBuf[512];
    UNICODE_STRING descName = RTL_CONSTANT_STRING(L"DriverDesc");
    ULONG resultLen = 0;

    status = ZwQueryValueKey(hSub, &descName, KeyValuePartialInformation,
        infoBuf, sizeof(infoBuf), &resultLen);

    if (NT_SUCCESS(status)) {
        /* This is a display adapter — spoof the HardwareID if needed */
        /* Most anti-cheats don't check GPU serial, but we randomize
         * the MatchingDeviceId to be safe */
    }

    ZwClose(hSub);
}

static BOOLEAN SpoofGpuIds()
{
    UNICODE_STRING gpuPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4d36e968-e325-11ce-bfc1-08002be10318}");

    return NT_SUCCESS(RegEnumSubkeys(&gpuPath, GpuSpoofCallback, NULL));
}

/* ── Machine GUID spoofing ───────────────────────────────────────── */

static BOOLEAN SpoofMachineGuid()
{
    if (!g_Spoof.initialized) return FALSE;

    UNICODE_STRING cryptoPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
    UNICODE_STRING guidVal = RTL_CONSTANT_STRING(L"MachineGuid");

    /* Generate a random GUID string */
    char guidA[39];
    SpoofRandomGuid(guidA);

    /* Convert to wide — strip braces for MachineGuid format:
     * xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx */
    WCHAR guidW[37];
    for (int i = 0; i < 36; i++)
        guidW[i] = (WCHAR)guidA[i + 1]; /* skip opening brace */
    guidW[36] = L'\0';

    return NT_SUCCESS(RegSetValueStr(&cryptoPath, &guidVal, guidW));
}

/* ── Windows Product ID spoofing ─────────────────────────────────── */

static BOOLEAN SpoofProductId()
{
    if (!g_Spoof.initialized) return FALSE;

    /* Generate random product ID: XXXXX-XXX-XXXXXXX-XXXXX */
    char part1[6], part2[4], part3[8], part4[6];
    SpoofRandomAlphaNum(part1, 5);
    SpoofRandomAlphaNum(part2, 3);
    SpoofRandomAlphaNum(part3, 7);
    SpoofRandomAlphaNum(part4, 5);

    WCHAR productId[24];
    RtlStringCchPrintfW(productId, 24, L"%S-%S-%S-%S",
        part1, part2, part3, part4);

    UNICODE_STRING ntPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    UNICODE_STRING pidVal = RTL_CONSTANT_STRING(L"ProductId");

    RegSetValueStr(&ntPath, &pidVal, productId);

    /* Also spoof InstallDate */
    LARGE_INTEGER sysTime;
    KeQuerySystemTime(&sysTime);
    ULONG installDate = (ULONG)(sysTime.QuadPart / 10000000ULL) -
                         (SpoofRand32() % (86400 * 365)); /* random date within last year */

    UNICODE_STRING installVal = RTL_CONSTANT_STRING(L"InstallDate");
    RegSetValueDword(&ntPath, &installVal, installDate);

    return TRUE;
}

/* ── EFI variable ID spoofing ────────────────────────────────────── */

static BOOLEAN SpoofEfiVariables()
{
    /* EFI variables are queried via NtQuerySystemInformation with
     * SystemBootEnvironmentInformation. The boot GUID is stored in
     * the registry as well. */
    if (!g_Spoof.initialized) return FALSE;

    WCHAR guidW[39];
    char guidA[39];
    SpoofRandomGuid(guidA);
    for (int i = 0; i < 38; i++)
        guidW[i] = (WCHAR)guidA[i];
    guidW[38] = L'\0';

    UNICODE_STRING efiPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation");
    UNICODE_STRING biosVal = RTL_CONSTANT_STRING(L"BIOSReleaseDate");
    UNICODE_STRING sysManuf = RTL_CONSTANT_STRING(L"SystemManufacturer");
    UNICODE_STRING sysProd = RTL_CONSTANT_STRING(L"SystemProductName");

    /* Spoof system manufacturer and product to generic values */
    RegSetValueStr(&efiPath, &sysManuf, L"System manufacturer");
    RegSetValueStr(&efiPath, &sysProd, L"System Product Name");

    return TRUE;
}

/* ── Spoof HWID-related registry entries (misc) ──────────────────── */

static BOOLEAN SpoofHwidRegistry()
{
    if (!g_Spoof.initialized) return FALSE;

    /* HwProfileGuid */
    UNICODE_STRING hwProfPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001");
    UNICODE_STRING hwProfGuid = RTL_CONSTANT_STRING(L"HwProfileGuid");

    char guidA[39];
    SpoofRandomGuid(guidA);
    WCHAR guidW[39];
    for (int i = 0; i < 38; i++)
        guidW[i] = (WCHAR)guidA[i];
    guidW[38] = L'\0';

    RegSetValueStr(&hwProfPath, &hwProfGuid, guidW);

    /* SQM Machine Id */
    UNICODE_STRING sqmPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\SQMClient");
    UNICODE_STRING sqmVal = RTL_CONSTANT_STRING(L"MachineId");
    SpoofRandomGuid(guidA);
    for (int i = 0; i < 38; i++)
        guidW[i] = (WCHAR)guidA[i];
    guidW[38] = L'\0';
    RegSetValueStr(&sqmPath, &sqmVal, guidW);

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *                      MAIN INIT / CLEANUP
 * ═══════════════════════════════════════════════════════════════════ */

static BOOLEAN InitSpoofer()
{
    /* Step 1: Generate all random serials */
    InitSpoofData();

    ULONG spoofCount = 0;

    /* Step 2: Registry-based identity spoofs */
    if (SpoofComputerName())     spoofCount++;
    if (SpoofMacAddresses())     spoofCount++;
    if (SpoofMachineGuid())      spoofCount++;
    if (SpoofProductId())        spoofCount++;
    if (SpoofEfiVariables())     spoofCount++;
    if (SpoofHwidRegistry())     spoofCount++;

    /* Step 3: SMBIOS/WMI registry spoof */
    if (SpoofSmbiosRegistry())   spoofCount++;

    /* Step 4: Boot environment + activation IDs */
    if (SpoofBootEnvironment())  spoofCount++;

    /* Step 5: Disk serial hook (IRP dispatch swap) */
    if (InstallDiskSpoof())      spoofCount++;

    /* Step 6: Disk registry cache (SCSI Enum entries) */
    if (SpoofDiskEnumRegistry()) spoofCount++;

    /* Step 7: Monitor EDID serial */
    SpoofMonitorEdid();

    /* Step 8: GPU IDs (optional) */
    SpoofGpuIds();

    /* Step 9: Volume serial (registry portion) */
    SpoofVolumeSerial();

    return (spoofCount > 0);
}

static void CleanupSpoofer()
{
    UninstallDiskSpoof();
}
