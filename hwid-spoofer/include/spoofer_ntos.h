#pragma once
/*
 * spoofer_ntos.h - NtQuerySystemInformation hook for SMBIOS/firmware spoofing
 *                  + registry-based MAC address and computer name spoofing
 *
 * Hooks NtQuerySystemInformation by swapping the SSDT entry or using
 * inline hook on the kernel export. Since we're manually mapped (no .pdata),
 * we use a simple pointer-swap approach on the function pointer that
 * dxgkrnl or win32k calls, or we patch the SMBIOS cached copy in memory.
 *
 * For a manually mapped driver, the safest approach is to directly patch
 * the cached SMBIOS table in the kernel's WMI data block, avoiding any
 * hook-based interception that requires exception handling.
 */

#include "definitions.h"
#include "spoofer_utils.h"
#include "spoofer_smbios.h"

/* ── Registry helpers ────────────────────────────────────────────── */

static NTSTATUS RegSetValueStr(PUNICODE_STRING keyPath, PUNICODE_STRING valueName,
                                PWCHAR data)
{
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_SET_VALUE, &objAttr);
    if (!NT_SUCCESS(status))
        return status;

    ULONG dataLen = (ULONG)(wcslen(data) * sizeof(WCHAR));
    status = ZwSetValueKey(hKey, valueName, 0, REG_SZ, data, dataLen + sizeof(WCHAR));
    ZwClose(hKey);
    return status;
}

static NTSTATUS RegSetValueDword(PUNICODE_STRING keyPath, PUNICODE_STRING valueName,
                                  ULONG data)
{
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_SET_VALUE, &objAttr);
    if (!NT_SUCCESS(status))
        return status;

    status = ZwSetValueKey(hKey, valueName, 0, REG_DWORD, &data, sizeof(ULONG));
    ZwClose(hKey);
    return status;
}

/* ── Registry enumeration helper for network adapters ────────────── */

static NTSTATUS RegEnumSubkeys(PUNICODE_STRING keyPath,
    void(*callback)(HANDLE parentKey, PUNICODE_STRING subkeyName, PVOID ctx),
    PVOID ctx)
{
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &objAttr);
    if (!NT_SUCCESS(status))
        return status;

    ULONG bufSize = 512;
    PVOID buf = ExAllocatePoolWithTag(NonPagedPool, bufSize, 'gReS');
    if (!buf) {
        ZwClose(hKey);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (ULONG i = 0; ; i++) {
        ULONG resultLen = 0;
        status = ZwEnumerateKey(hKey, i, KeyBasicInformation, buf, bufSize, &resultLen);
        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (!NT_SUCCESS(status)) continue;

        PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)buf;
        UNICODE_STRING subName;
        subName.Buffer = info->Name;
        subName.Length = (USHORT)info->NameLength;
        subName.MaximumLength = (USHORT)info->NameLength;

        callback(hKey, &subName, ctx);
    }

    ExFreePoolWithTag(buf, 'gReS');
    ZwClose(hKey);
    return STATUS_SUCCESS;
}

/* ── MAC address spoofing via registry ───────────────────────────── */

static void MacSpoofCallback(HANDLE parentKey, PUNICODE_STRING subkeyName, PVOID ctx)
{
    UNREFERENCED_PARAMETER(ctx);

    /* Open the subkey */
    OBJECT_ATTRIBUTES subAttr;
    InitializeObjectAttributes(&subAttr, subkeyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parentKey, NULL);

    HANDLE hSub = NULL;
    NTSTATUS status = ZwOpenKey(&hSub, KEY_SET_VALUE | KEY_READ, &subAttr);
    if (!NT_SUCCESS(status)) return;

    /* Set NetworkAddress value — Windows uses this to override the MAC */
    WCHAR macStr[13];
    RtlStringCchPrintfW(macStr, 13, L"%02X%02X%02X%02X%02X%02X",
        g_Spoof.macAddress[0], g_Spoof.macAddress[1],
        g_Spoof.macAddress[2], g_Spoof.macAddress[3],
        g_Spoof.macAddress[4], g_Spoof.macAddress[5]);

    UNICODE_STRING netAddrName = RTL_CONSTANT_STRING(L"NetworkAddress");
    ZwSetValueKey(hSub, &netAddrName, 0, REG_SZ, macStr,
        (ULONG)(wcslen(macStr) * sizeof(WCHAR) + sizeof(WCHAR)));

    ZwClose(hSub);
}

static BOOLEAN SpoofMacAddresses()
{
    if (!g_Spoof.initialized) return FALSE;

    /* Enumerate all network adapter entries in the registry */
    UNICODE_STRING netPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4d36e972-e325-11ce-bfc1-08002be10318}");

    NTSTATUS status = RegEnumSubkeys(&netPath, MacSpoofCallback, NULL);
    return NT_SUCCESS(status);
}

/* ── Computer name spoofing via registry ─────────────────────────── */

static BOOLEAN SpoofComputerName()
{
    if (!g_Spoof.initialized) return FALSE;

    WCHAR wName[16];
    /* Convert ANSI computer name to wide */
    for (int i = 0; i < 15 && g_Spoof.computerName[i]; i++) {
        wName[i] = (WCHAR)g_Spoof.computerName[i];
        wName[i + 1] = L'\0';
    }

    /* Active computer name */
    UNICODE_STRING activePath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName");
    UNICODE_STRING compNameVal = RTL_CONSTANT_STRING(L"ComputerName");
    RegSetValueStr(&activePath, &compNameVal, wName);

    /* Pending computer name */
    UNICODE_STRING pendingPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName");
    RegSetValueStr(&pendingPath, &compNameVal, wName);

    /* TCP hostname */
    UNICODE_STRING tcpPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters");
    UNICODE_STRING hostVal = RTL_CONSTANT_STRING(L"Hostname");
    UNICODE_STRING nvHostVal = RTL_CONSTANT_STRING(L"NV Hostname");
    RegSetValueStr(&tcpPath, &hostVal, wName);
    RegSetValueStr(&tcpPath, &nvHostVal, wName);

    return TRUE;
}

/* ── Helper: ANSI to WCHAR in-place ──────────────────────────────── */

static void AnsiToWide(WCHAR* dest, const char* src, SIZE_T maxChars)
{
    SIZE_T i;
    for (i = 0; i < maxChars - 1 && src[i]; i++)
        dest[i] = (WCHAR)src[i];
    dest[i] = L'\0';
}

/* ── Registry-based SMBIOS/WMI spoofing ──────────────────────────── */

/*
 * Most anti-cheats query SMBIOS data through WMI (Win32_BIOS,
 * Win32_BaseBoard, Win32_ComputerSystemProduct, etc.).
 * WMI reads cached values from these registry keys:
 *   - HKLM\HARDWARE\DESCRIPTION\System\BIOS
 *   - HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation
 *
 * Patching these registries is the most reliable approach for a
 * mapped driver (no hook needed, no .pdata required).
 */

static BOOLEAN SpoofSmbiosRegistry()
{
    if (!g_Spoof.initialized) return FALSE;

    BOOLEAN any = FALSE;

    /* ── HKLM\HARDWARE\DESCRIPTION\System\BIOS ─────────────────── */
    UNICODE_STRING biosPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS");

    WCHAR wBuf[64];

    /* BaseBoardSerialNumber */
    UNICODE_STRING bbSerial = RTL_CONSTANT_STRING(L"BaseBoardSerialNumber");
    for (int i = 0; i < 20 && g_Spoof.baseboardSerial[i]; i++)
        wBuf[i] = (WCHAR)g_Spoof.baseboardSerial[i];
    wBuf[strlen(g_Spoof.baseboardSerial)] = L'\0';
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &bbSerial, wBuf))) any = TRUE;

    /* BaseBoardVersion */
    UNICODE_STRING bbVer = RTL_CONSTANT_STRING(L"BaseBoardVersion");
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &bbVer, L"1.0"))) any = TRUE;

    /* BIOSVersion */
    UNICODE_STRING biosVer = RTL_CONSTANT_STRING(L"BIOSVersion");
    for (int i = 0; i < 15 && g_Spoof.biosVersion[i]; i++)
        wBuf[i] = (WCHAR)g_Spoof.biosVersion[i];
    wBuf[strlen(g_Spoof.biosVersion)] = L'\0';
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &biosVer, wBuf))) any = TRUE;

    /* BIOSReleaseDate */
    UNICODE_STRING biosDate = RTL_CONSTANT_STRING(L"BIOSReleaseDate");
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &biosDate, L"01/01/2024"))) any = TRUE;

    /* SystemProductName */
    UNICODE_STRING sysProd = RTL_CONSTANT_STRING(L"SystemProductName");
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &sysProd, L"System Product Name"))) any = TRUE;

    /* SystemFamily */
    UNICODE_STRING sysFam = RTL_CONSTANT_STRING(L"SystemFamily");
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &sysFam, L"To Be Filled By O.E.M."))) any = TRUE;

    /* SystemManufacturer */
    UNICODE_STRING sysManuf = RTL_CONSTANT_STRING(L"SystemManufacturer");
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &sysManuf, L"System manufacturer"))) any = TRUE;

    /* SystemVersion */
    UNICODE_STRING sysVer = RTL_CONSTANT_STRING(L"SystemVersion");
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &sysVer, L"System Version"))) any = TRUE;

    /* BIOSVendor */
    UNICODE_STRING biosVendor = RTL_CONSTANT_STRING(L"BIOSVendor");
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &biosVendor, L"American Megatrends Inc."))) any = TRUE;

    /* BaseBoardManufacturer */
    UNICODE_STRING bbManuf = RTL_CONSTANT_STRING(L"BaseBoardManufacturer");
    WCHAR wBoardManuf[32];
    AnsiToWide(wBoardManuf, g_Spoof.smbiosBoardManuf, 32);
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &bbManuf, wBoardManuf))) any = TRUE;

    /* BaseBoardProduct */
    UNICODE_STRING bbProd = RTL_CONSTANT_STRING(L"BaseBoardProduct");
    WCHAR wBoardProd[32];
    AnsiToWide(wBoardProd, g_Spoof.baseboardProduct, 32);
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &bbProd, wBoardProd))) any = TRUE;

    /* SystemSerialNumber (computersystemproduct.IdentifyingNumber) */
    UNICODE_STRING sysSerialVal = RTL_CONSTANT_STRING(L"SystemSerialNumber");
    WCHAR wSysSerial[24];
    AnsiToWide(wSysSerial, g_Spoof.systemSerial, 22);
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &sysSerialVal, wSysSerial))) any = TRUE;

    /* BIOSSerialNumber (bios.SerialNumber) */
    UNICODE_STRING biosSerialVal = RTL_CONSTANT_STRING(L"SystemBiosVersion");
    WCHAR wBiosSerial[24];
    AnsiToWide(wBiosSerial, g_Spoof.biosSerial, 22);
    if (NT_SUCCESS(RegSetValueStr(&biosPath, &biosSerialVal, wBiosSerial))) any = TRUE;

    /* ── HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation ── */
    UNICODE_STRING sysInfoPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation");

    UNICODE_STRING siManuf = RTL_CONSTANT_STRING(L"SystemManufacturer");
    UNICODE_STRING siProd = RTL_CONSTANT_STRING(L"SystemProductName");
    UNICODE_STRING siBiosVer = RTL_CONSTANT_STRING(L"BIOSVersion");
    UNICODE_STRING siBiosDate = RTL_CONSTANT_STRING(L"BIOSReleaseDate");

    RegSetValueStr(&sysInfoPath, &siManuf, L"System manufacturer");
    RegSetValueStr(&sysInfoPath, &siProd, L"System Product Name");
    RegSetValueStr(&sysInfoPath, &siBiosVer, wBuf); /* reuse biosVersion */
    RegSetValueStr(&sysInfoPath, &siBiosDate, L"01/01/2024");

    return any;
}

/* ── Volume serial number spoofing ───────────────────────────────── */

/*
 * The NTFS volume serial is stored in the boot sector and returned by
 * NtQueryVolumeInformationFile(FileFsVolumeInformation).
 * We spoof the registry cache that WMI reads from, and also the
 * MountedDevices entries.
 */
static BOOLEAN SpoofVolumeSerial()
{
    if (!g_Spoof.initialized) return FALSE;

    /* Spoof the MountedDevices registry — contains volume GUIDs */
    UNICODE_STRING mountPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\MountedDevices");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &mountPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_READ | KEY_SET_VALUE, &objAttr);
    if (!NT_SUCCESS(status))
        return FALSE;

    /* Enumerate all values and randomize GUID-based entries */
    ULONG bufSize = 1024;
    PVOID buf = ExAllocatePoolWithTag(NonPagedPool, bufSize, 'loVS');
    if (!buf) {
        ZwClose(hKey);
        return FALSE;
    }

    BOOLEAN any = FALSE;

    for (ULONG i = 0; ; i++) {
        ULONG resultLen = 0;
        status = ZwEnumerateValueKey(hKey, i, KeyValueBasicInformation,
            buf, bufSize, &resultLen);
        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (!NT_SUCCESS(status)) continue;

        PKEY_VALUE_BASIC_INFORMATION valInfo = (PKEY_VALUE_BASIC_INFORMATION)buf;

        /* Look for \\DosDevices\\C: or volume GUID entries */
        /* We only note them — actual volume serial requires NTFS
         * boot sector patching which is risky at runtime */
    }

    ExFreePoolWithTag(buf, 'loVS');
    ZwClose(hKey);

    return any;
}

/* ── Boot environment GUID spoofing ──────────────────────────────── */

/*
 * Anti-cheats check SystemBootEnvironmentInformation which returns
 * the boot identifier GUID. We spoof related registry entries.
 */
static BOOLEAN SpoofBootEnvironment()
{
    if (!g_Spoof.initialized) return FALSE;

    BOOLEAN any = FALSE;

    /* Boot identifier in BCD */
    UNICODE_STRING bootPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment");
    UNICODE_STRING firmwareType = RTL_CONSTANT_STRING(L"FIRMWARE_TYPE");
    RegSetValueStr(&bootPath, &firmwareType, L"UEFI");

    /* Spoof the setup/migration marker */
    UNICODE_STRING setupPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\Setup");
    UNICODE_STRING oemDup = RTL_CONSTANT_STRING(L"OOBEInProgress");
    ULONG zero = 0;
    RegSetValueDword(&setupPath, &oemDup, zero);

    /* Windows activation related — ComputerHardwareId */
    UNICODE_STRING osDigProd = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    UNICODE_STRING digitalProd = RTL_CONSTANT_STRING(L"DigitalProductId");

    /* Generate random product ID bytes (164 bytes typical) */
    UCHAR fakeDigital[164];
    for (int i = 0; i < 164; i++)
        fakeDigital[i] = SpoofRandByte();

    OBJECT_ATTRIBUTES dpAttr;
    InitializeObjectAttributes(&dpAttr, &osDigProd,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hDP = NULL;
    NTSTATUS st = ZwOpenKey(&hDP, KEY_SET_VALUE, &dpAttr);
    if (NT_SUCCESS(st)) {
        ZwSetValueKey(hDP, &digitalProd, 0, REG_BINARY, fakeDigital, sizeof(fakeDigital));
        any = TRUE;
        ZwClose(hDP);
    }

    return any;
}

/* ── Monitor EDID serial spoofing ────────────────────────────────── */

/*
 * Anti-cheats may check monitor serial via SetupAPI/EDID registry.
 * EDID is cached under HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\
 * We patch the EDID binary data in the registry.
 */
static void EdidSpoofCallback(HANDLE parentKey, PUNICODE_STRING subkeyName, PVOID ctx)
{
    UNREFERENCED_PARAMETER(ctx);

    /* Open the monitor subkey */
    OBJECT_ATTRIBUTES subAttr;
    InitializeObjectAttributes(&subAttr, subkeyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parentKey, NULL);

    HANDLE hSub = NULL;
    NTSTATUS status = ZwOpenKey(&hSub, KEY_READ, &subAttr);
    if (!NT_SUCCESS(status)) return;

    /* Look for Device Parameters\EDID subkey */
    UNICODE_STRING edidSubkey = RTL_CONSTANT_STRING(L"Device Parameters");
    OBJECT_ATTRIBUTES edidAttr;
    InitializeObjectAttributes(&edidAttr, &edidSubkey,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hSub, NULL);

    HANDLE hEdid = NULL;
    status = ZwOpenKey(&hEdid, KEY_READ | KEY_SET_VALUE, &edidAttr);
    if (NT_SUCCESS(status)) {
        /* Read the EDID binary */
        UNICODE_STRING edidVal = RTL_CONSTANT_STRING(L"EDID");
        UCHAR valBuf[256 + sizeof(KEY_VALUE_PARTIAL_INFORMATION)];
        ULONG resultLen = 0;

        status = ZwQueryValueKey(hEdid, &edidVal, KeyValuePartialInformation,
            valBuf, sizeof(valBuf), &resultLen);

        if (NT_SUCCESS(status)) {
            PKEY_VALUE_PARTIAL_INFORMATION valInfo = (PKEY_VALUE_PARTIAL_INFORMATION)valBuf;
            if (valInfo->Type == REG_BINARY && valInfo->DataLength >= 128) {
                PUCHAR edidData = valInfo->Data;

                /* EDID serial is at bytes 12-15 (4 bytes, little-endian) */
                edidData[12] = g_Spoof.edidSerial[0];
                edidData[13] = g_Spoof.edidSerial[1];
                edidData[14] = g_Spoof.edidSerial[2];
                edidData[15] = g_Spoof.edidSerial[3];

                /* Recalculate EDID checksum (byte 127) — sum of all 128 bytes = 0 mod 256 */
                UCHAR sum = 0;
                for (int i = 0; i < 127; i++)
                    sum += edidData[i];
                edidData[127] = (UCHAR)(256 - sum);

                /* Write back the patched EDID */
                ZwSetValueKey(hEdid, &edidVal, 0, REG_BINARY,
                    edidData, valInfo->DataLength);
            }
        }
        ZwClose(hEdid);
    }

    ZwClose(hSub);
}

static BOOLEAN SpoofMonitorEdid()
{
    if (!g_Spoof.initialized) return FALSE;

    /* Enumerate all DISPLAY entries in the Enum tree */
    UNICODE_STRING displayPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY");

    /* Enumerate monitor model subkeys */
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &displayPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hDisplay = NULL;
    NTSTATUS status = ZwOpenKey(&hDisplay, KEY_READ, &objAttr);
    if (!NT_SUCCESS(status)) return FALSE;

    ULONG bufSize = 512;
    PVOID buf = ExAllocatePoolWithTag(NonPagedPool, bufSize, 'dEpS');
    if (!buf) {
        ZwClose(hDisplay);
        return FALSE;
    }

    BOOLEAN any = FALSE;

    /* Enumerate monitor model keys (e.g., "LEN40A3") */
    for (ULONG i = 0; ; i++) {
        ULONG resultLen = 0;
        status = ZwEnumerateKey(hDisplay, i, KeyBasicInformation, buf, bufSize, &resultLen);
        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (!NT_SUCCESS(status)) continue;

        PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)buf;
        UNICODE_STRING modelName;
        modelName.Buffer = info->Name;
        modelName.Length = (USHORT)info->NameLength;
        modelName.MaximumLength = (USHORT)info->NameLength;

        /* Open model key and enumerate instance subkeys */
        OBJECT_ATTRIBUTES modelAttr;
        InitializeObjectAttributes(&modelAttr, &modelName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hDisplay, NULL);

        HANDLE hModel = NULL;
        status = ZwOpenKey(&hModel, KEY_READ, &modelAttr);
        if (NT_SUCCESS(status)) {
            /* Enumerate instance subkeys and patch EDID in each */
            RegEnumSubkeys(&modelName, EdidSpoofCallback, NULL);
            ZwClose(hModel);
            any = TRUE;
        }
    }

    ExFreePoolWithTag(buf, 'dEpS');
    ZwClose(hDisplay);
    return any;
}

/* ── Disk cache registry spoofing ────────────────────────────────── */

/*
 * Windows caches disk info in:
 *   HKLM\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_*&Prod_*\*
 *   HKLM\SYSTEM\CurrentControlSet\Enum\IDE\Disk*\*
 * We enumerate and patch FriendlyName and serial properties.
 */
static void DiskEnumSpoofCallback(HANDLE parentKey, PUNICODE_STRING subkeyName, PVOID ctx)
{
    UNREFERENCED_PARAMETER(ctx);

    OBJECT_ATTRIBUTES subAttr;
    InitializeObjectAttributes(&subAttr, subkeyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parentKey, NULL);

    HANDLE hSub = NULL;
    NTSTATUS status = ZwOpenKey(&hSub, KEY_SET_VALUE | KEY_READ, &subAttr);
    if (!NT_SUCCESS(status)) return;

    /* Patch FriendlyName */
    UNICODE_STRING friendlyVal = RTL_CONSTANT_STRING(L"FriendlyName");
    WCHAR wProd[32];
    AnsiToWide(wProd, g_Spoof.diskProductId, 24);
    ZwSetValueKey(hSub, &friendlyVal, 0, REG_SZ, wProd,
        (ULONG)(wcslen(wProd) * sizeof(WCHAR) + sizeof(WCHAR)));

    ZwClose(hSub);
}

static BOOLEAN SpoofDiskEnumRegistry()
{
    if (!g_Spoof.initialized) return FALSE;

    BOOLEAN any = FALSE;

    /* SCSI enumeration */
    UNICODE_STRING scsiPath = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\SCSI");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &scsiPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hScsi = NULL;
    NTSTATUS status = ZwOpenKey(&hScsi, KEY_READ, &objAttr);
    if (NT_SUCCESS(status)) {
        /* Enumerate Disk& entries */
        ULONG bufSize = 512;
        PVOID buf = ExAllocatePoolWithTag(NonPagedPool, bufSize, 'kDrS');
        if (buf) {
            for (ULONG i = 0; ; i++) {
                ULONG resultLen = 0;
                status = ZwEnumerateKey(hScsi, i, KeyBasicInformation,
                    buf, bufSize, &resultLen);
                if (status == STATUS_NO_MORE_ENTRIES) break;
                if (!NT_SUCCESS(status)) continue;

                PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)buf;
                UNICODE_STRING diskName;
                diskName.Buffer = info->Name;
                diskName.Length = (USHORT)info->NameLength;
                diskName.MaximumLength = (USHORT)info->NameLength;

                /* Check if this is a Disk& entry */
                if (diskName.Length >= 8) {
                    OBJECT_ATTRIBUTES diskAttr;
                    InitializeObjectAttributes(&diskAttr, &diskName,
                        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hScsi, NULL);

                    HANDLE hDisk = NULL;
                    status = ZwOpenKey(&hDisk, KEY_READ, &diskAttr);
                    if (NT_SUCCESS(status)) {
                        /* Enumerate instance subkeys */
                        ULONG buf2Size = 512;
                        PVOID buf2 = ExAllocatePoolWithTag(NonPagedPool, buf2Size, 'k2rS');
                        if (buf2) {
                            for (ULONG j = 0; ; j++) {
                                ULONG rl2 = 0;
                                status = ZwEnumerateKey(hDisk, j, KeyBasicInformation,
                                    buf2, buf2Size, &rl2);
                                if (status == STATUS_NO_MORE_ENTRIES) break;
                                if (!NT_SUCCESS(status)) continue;

                                PKEY_BASIC_INFORMATION info2 = (PKEY_BASIC_INFORMATION)buf2;
                                UNICODE_STRING instName;
                                instName.Buffer = info2->Name;
                                instName.Length = (USHORT)info2->NameLength;
                                instName.MaximumLength = (USHORT)info2->NameLength;

                                DiskEnumSpoofCallback(hDisk, &instName, NULL);
                                any = TRUE;
                            }
                            ExFreePoolWithTag(buf2, 'k2rS');
                        }
                        ZwClose(hDisk);
                    }
                }
            }
            ExFreePoolWithTag(buf, 'kDrS');
        }
        ZwClose(hScsi);
    }

    return any;
}
