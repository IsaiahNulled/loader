#pragma once
/*
 * spoofer_smbios.h - SMBIOS firmware table spoofing
 *
 * Hooks NtQuerySystemInformation(SystemFirmwareTableInformation) to
 * intercept SMBIOS table reads and replace serial numbers, UUIDs,
 * baseboard info, BIOS version, etc.
 *
 * SMBIOS table types we spoof:
 *   Type 0 - BIOS Information (manufacturer, version, serial)
 *   Type 1 - System Information (manufacturer, product, serial, UUID)
 *   Type 2 - Baseboard Information (manufacturer, product, serial, version)
 *   Type 3 - System Enclosure (serial, asset tag)
 */

#include "definitions.h"
#include "spoofer_utils.h"

/* ── SMBIOS structures ───────────────────────────────────────────── */

#pragma pack(push, 1)

typedef struct _SMBIOS_HEADER {
    UCHAR  Type;
    UCHAR  Length;
    USHORT Handle;
} SMBIOS_HEADER, *PSMBIOS_HEADER;

/* Type 0 - BIOS Information */
typedef struct _SMBIOS_TYPE0 {
    SMBIOS_HEADER Header;
    UCHAR  Vendor;           /* string index */
    UCHAR  BiosVersion;      /* string index */
    USHORT BiosStartSegment;
    UCHAR  BiosReleaseDate;  /* string index */
    UCHAR  BiosRomSize;
    ULONG64 BiosCharacteristics;
} SMBIOS_TYPE0;

/* Type 1 - System Information */
typedef struct _SMBIOS_TYPE1 {
    SMBIOS_HEADER Header;
    UCHAR  Manufacturer;     /* string index */
    UCHAR  ProductName;      /* string index */
    UCHAR  Version;          /* string index */
    UCHAR  SerialNumber;     /* string index */
    UCHAR  UUID[16];
    UCHAR  WakeUpType;
    UCHAR  SKUNumber;        /* string index */
    UCHAR  Family;           /* string index */
} SMBIOS_TYPE1;

/* Type 2 - Baseboard Information */
typedef struct _SMBIOS_TYPE2 {
    SMBIOS_HEADER Header;
    UCHAR  Manufacturer;     /* string index */
    UCHAR  Product;          /* string index */
    UCHAR  Version;          /* string index */
    UCHAR  SerialNumber;     /* string index */
    UCHAR  AssetTag;         /* string index */
    UCHAR  FeatureFlags;
    UCHAR  LocationInChassis; /* string index */
    USHORT ChassisHandle;
    UCHAR  BoardType;
} SMBIOS_TYPE2;

/* Type 3 - System Enclosure */
typedef struct _SMBIOS_TYPE3 {
    SMBIOS_HEADER Header;
    UCHAR  Manufacturer;     /* string index */
    UCHAR  Type;
    UCHAR  Version;          /* string index */
    UCHAR  SerialNumber;     /* string index */
    UCHAR  AssetTag;         /* string index */
} SMBIOS_TYPE3;

#pragma pack(pop)

/* ── Firmware table query structures ─────────────────────────────── */

#define FIRMWARE_TABLE_PROVIDER_RSMB 'RSMB'

/* SystemFirmwareTableInformation = 76 */
#define SystemFirmwareTableInformation 76

/* Raw SMBIOS data header that Windows puts at start of RSMB table */
typedef struct _RAW_SMBIOS_DATA {
    UCHAR  Used20CallingMethod;
    UCHAR  SMBIOSMajorVersion;
    UCHAR  SMBIOSMinorVersion;
    UCHAR  DmiRevision;
    ULONG  Length;
    UCHAR  SMBIOSTableData[1];
} RAW_SMBIOS_DATA, *PRAW_SMBIOS_DATA;

/* ── SMBIOS string manipulation ──────────────────────────────────── */

/*
 * Get pointer to the Nth string in an SMBIOS structure's string area.
 * SMBIOS strings are 1-indexed. String area starts after the formatted area.
 * Returns NULL if index is 0 or string not found.
 */
static PCHAR SmbiosGetString(PSMBIOS_HEADER header, UCHAR index)
{
    if (index == 0) return NULL;

    PCHAR strArea = (PCHAR)header + header->Length;
    UCHAR current = 1;

    while (*strArea) {
        if (current == index)
            return strArea;
        strArea += strlen(strArea) + 1;
        current++;
    }
    return NULL;
}

/*
 * Get the total size of an SMBIOS structure (formatted area + string area).
 * The string area ends with a double null terminator.
 */
static ULONG SmbiosStructureSize(PSMBIOS_HEADER header)
{
    PCHAR p = (PCHAR)header + header->Length;

    /* Walk past all strings */
    while (*p) {
        p += strlen(p) + 1;
    }
    p++; /* skip the final null */

    return (ULONG)(p - (PCHAR)header);
}

/*
 * Replace an SMBIOS string in-place. The new string must be <= the old string
 * length. If shorter, we pad with spaces (SMBIOS readers trim whitespace).
 * Returns TRUE if replaced successfully.
 *
 * NOTE: This modifies the buffer in-place. For strings longer than the original,
 * we truncate to the original length to avoid shifting the entire table.
 */
static BOOLEAN SmbiosReplaceString(PSMBIOS_HEADER header, UCHAR index,
                                    const char* newStr, ULONG totalBufRemaining)
{
    PCHAR oldStr = SmbiosGetString(header, index);
    if (!oldStr) return FALSE;

    SIZE_T oldLen = strlen(oldStr);
    SIZE_T newLen = strlen(newStr);

    if (newLen <= oldLen) {
        RtlCopyMemory(oldStr, newStr, newLen);
        /* Pad remainder with spaces */
        for (SIZE_T i = newLen; i < oldLen; i++)
            oldStr[i] = ' ';
    } else {
        /* Truncate new string to fit */
        RtlCopyMemory(oldStr, newStr, oldLen);
    }
    return TRUE;
}

/* ── Main SMBIOS spoofing function ───────────────────────────────── */

/*
 * Walk the SMBIOS table buffer and replace all target serials/UUIDs.
 * Called after NtQuerySystemInformation returns the firmware table.
 */
static void SpoofSmbiosTable(PUCHAR tableData, ULONG tableLength)
{
    if (!g_Spoof.initialized) return;

    PUCHAR p = tableData;
    PUCHAR end = tableData + tableLength;

    while (p < end) {
        PSMBIOS_HEADER header = (PSMBIOS_HEADER)p;

        if (p + sizeof(SMBIOS_HEADER) > end) break;
        if (header->Length < sizeof(SMBIOS_HEADER)) break;
        if (p + header->Length > end) break;

        ULONG structSize = SmbiosStructureSize(header);
        if (p + structSize > end) break;

        ULONG remaining = (ULONG)(end - p);

        switch (header->Type) {
        case 0: /* BIOS Information */
        {
            SMBIOS_TYPE0* bios = (SMBIOS_TYPE0*)header;
            if (header->Length >= sizeof(SMBIOS_TYPE0)) {
                SmbiosReplaceString(header, bios->BiosVersion,
                    g_Spoof.biosVersion, remaining);
            }
            break;
        }
        case 1: /* System Information */
        {
            SMBIOS_TYPE1* sys = (SMBIOS_TYPE1*)header;
            if (header->Length >= offsetof(SMBIOS_TYPE1, WakeUpType)) {
                /* Spoof UUID */
                RtlCopyMemory(sys->UUID, g_Spoof.systemUuid, 16);
                /* Spoof serial */
                SmbiosReplaceString(header, sys->SerialNumber,
                    g_Spoof.biosSerial, remaining);
            }
            break;
        }
        case 2: /* Baseboard Information */
        {
            SMBIOS_TYPE2* board = (SMBIOS_TYPE2*)header;
            if (header->Length >= offsetof(SMBIOS_TYPE2, FeatureFlags)) {
                SmbiosReplaceString(header, board->SerialNumber,
                    g_Spoof.baseboardSerial, remaining);
            }
            break;
        }
        case 3: /* System Enclosure */
        {
            SMBIOS_TYPE3* enc = (SMBIOS_TYPE3*)header;
            if (header->Length >= offsetof(SMBIOS_TYPE3, AssetTag) + 1) {
                SmbiosReplaceString(header, enc->SerialNumber,
                    g_Spoof.biosSerial, remaining);
            }
            break;
        }
        case 127: /* End-of-Table */
            return;
        }

        p += structSize;
    }
}
