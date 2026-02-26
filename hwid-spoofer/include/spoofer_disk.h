#pragma once
/*
 * spoofer_disk.h - Comprehensive disk serial number spoofing
 *
 * Hooks IRP_MJ_DEVICE_CONTROL dispatch of disk driver objects to intercept:
 *   - IOCTL_STORAGE_QUERY_PROPERTY (StorageDeviceProperty)        → serial, product, vendor
 *   - IOCTL_STORAGE_QUERY_PROPERTY (StorageDeviceIdProperty)      → VPD Page 83 / SCSI IDs
 *   - IOCTL_STORAGE_QUERY_PROPERTY (StorageDeviceUniqueIdProperty) → UniqueId GUID
 *   - SMART_RCV_DRIVE_DATA / IOCTL_ATA_PASS_THROUGH               → ATA IDENTIFY serial
 *   - IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS                        → disk extent info
 */

#include "definitions.h"
#include "spoofer_utils.h"

/* ── Storage IOCTLs ──────────────────────────────────────────────── */

#ifndef IOCTL_STORAGE_QUERY_PROPERTY
#define IOCTL_STORAGE_QUERY_PROPERTY 0x002D1400
#endif

#ifndef IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
#define IOCTL_DISK_GET_DRIVE_GEOMETRY_EX 0x000700A0
#endif

#ifndef SMART_RCV_DRIVE_DATA
#define SMART_RCV_DRIVE_DATA 0x0007C088
#endif

#ifndef IOCTL_ATA_PASS_THROUGH
#define IOCTL_ATA_PASS_THROUGH 0x0004D02C
#endif

#ifndef IOCTL_SCSI_MINIPORT
#define IOCTL_SCSI_MINIPORT 0x0004D008
#endif

/* ── Storage property enums and structures ───────────────────────── */

typedef enum _STORAGE_PROPERTY_ID_EX {
    StorageDeviceProperty_Ex          = 0,
    StorageAdapterProperty_Ex         = 1,
    StorageDeviceIdProperty_Ex        = 3,
    StorageDeviceUniqueIdProperty_Ex  = 5,
    StorageDeviceWriteCacheProperty_Ex = 8,
} STORAGE_PROPERTY_ID_EX;

typedef enum _STORAGE_QUERY_TYPE_EX {
    PropertyStandardQuery_Ex = 0,
    PropertyExistsQuery_Ex   = 1,
} STORAGE_QUERY_TYPE_EX;

typedef struct _STORAGE_PROPERTY_QUERY_EX {
    ULONG PropertyId;
    ULONG QueryType;
    UCHAR AdditionalParameters[1];
} STORAGE_PROPERTY_QUERY_EX, *PSTORAGE_PROPERTY_QUERY_EX;

typedef struct _STORAGE_DEVICE_DESCRIPTOR_EX {
    ULONG   Version;
    ULONG   Size;
    UCHAR   DeviceType;
    UCHAR   DeviceTypeModifier;
    BOOLEAN RemovableMedia;
    BOOLEAN CommandQueueing;
    ULONG   VendorIdOffset;
    ULONG   ProductIdOffset;
    ULONG   ProductRevisionOffset;
    ULONG   SerialNumberOffset;
    UCHAR   BusType;
    ULONG   RawPropertiesLength;
    UCHAR   RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR_EX, *PSTORAGE_DEVICE_DESCRIPTOR_EX;

/* STORAGE_DEVICE_ID_DESCRIPTOR — returned for StorageDeviceIdProperty */
typedef struct _STORAGE_IDENTIFIER_EX {
    ULONG  CodeSet;          /* StorageIdCodeSet */
    ULONG  Type;             /* StorageIdType */
    USHORT IdentifierSize;
    USHORT NextOffset;
    ULONG  Association;      /* StorageIdAssociation */
    UCHAR  Identifier[1];
} STORAGE_IDENTIFIER_EX, *PSTORAGE_IDENTIFIER_EX;

typedef struct _STORAGE_DEVICE_ID_DESCRIPTOR_EX {
    ULONG  Version;
    ULONG  Size;
    ULONG  NumberOfIdentifiers;
    UCHAR  Identifiers[1];
} STORAGE_DEVICE_ID_DESCRIPTOR_EX, *PSTORAGE_DEVICE_ID_DESCRIPTOR_EX;

/* STORAGE_DEVICE_UNIQUE_IDENTIFIER — returned for StorageDeviceUniqueIdProperty */
typedef struct _STORAGE_DEVICE_UNIQUE_IDENTIFIER_EX {
    ULONG  Version;
    ULONG  Size;
    ULONG  StorageDeviceIdSize;
    ULONG  StorageDeviceOffset;
    ULONG  StorageAdapterIdSize;
    ULONG  StorageAdapterOffset;
} STORAGE_DEVICE_UNIQUE_IDENTIFIER_EX, *PSTORAGE_DEVICE_UNIQUE_IDENTIFIER_EX;

/* ATA IDENTIFY data — serial is at words 10-19 (bytes 20-39) */
#define ATA_IDENTIFY_SERIAL_OFFSET  20
#define ATA_IDENTIFY_SERIAL_LEN     20
#define ATA_IDENTIFY_MODEL_OFFSET   54
#define ATA_IDENTIFY_MODEL_LEN      40
#define ATA_IDENTIFY_FW_OFFSET      46
#define ATA_IDENTIFY_FW_LEN         8

/* ATA_PASS_THROUGH_EX structure */
typedef struct _ATA_PASS_THROUGH_EX_S {
    USHORT Length;
    USHORT AtaFlags;
    UCHAR  PathId;
    UCHAR  TargetId;
    UCHAR  Lun;
    UCHAR  ReservedAsUchar;
    ULONG  DataTransferLength;
    ULONG  TimeOutValue;
    ULONG  ReservedAsUlong;
    ULONG_PTR DataBufferOffset;
    UCHAR  PreviousTaskFile[8];
    UCHAR  CurrentTaskFile[8];
} ATA_PASS_THROUGH_EX_S;

/* SENDCMDINPARAMS for SMART */
typedef struct _SENDCMDINPARAMS_S {
    ULONG  cBufferSize;
    UCHAR  irDriveRegs[8];
    UCHAR  bDriveNumber;
    UCHAR  bReserved[3];
    ULONG  dwReserved[4];
    UCHAR  bBuffer[1];
} SENDCMDINPARAMS_S;

typedef struct _SENDCMDOUTPARAMS_S {
    ULONG  cBufferSize;
    UCHAR  DriverStatus[12];
    UCHAR  bBuffer[1];
} SENDCMDOUTPARAMS_S;

/* ── Disk hook state ─────────────────────────────────────────────── */

#define MAX_DISK_HOOKS 12

typedef struct _DISK_HOOK_ENTRY {
    PDRIVER_OBJECT  driverObject;
    PDRIVER_DISPATCH originalDispatch;
    BOOLEAN         active;
} DISK_HOOK_ENTRY;

static DISK_HOOK_ENTRY g_DiskHooks[MAX_DISK_HOOKS] = { 0 };
static LONG g_DiskHookCount = 0;

/* ── Helper: replace string in buffer (truncate or pad) ──────────── */

static void DiskReplaceString(char* dest, SIZE_T destMaxLen,
                               const char* src, SIZE_T srcLen)
{
    if (destMaxLen == 0) return;
    SIZE_T copyLen = (srcLen < destMaxLen) ? srcLen : destMaxLen;
    RtlCopyMemory(dest, src, copyLen);
    if (copyLen < destMaxLen)
        dest[copyLen] = '\0';
}

/* ── Helper: swap byte pairs for ATA strings (word-swapped) ──────── */

static void DiskSetAtaString(PUCHAR dest, const char* src, SIZE_T fieldLen)
{
    SIZE_T srcLen = strlen(src);
    /* ATA strings are space-padded and byte-swapped per word */
    RtlFillMemory(dest, fieldLen, ' ');
    for (SIZE_T i = 0; i < fieldLen && i < srcLen; i += 2) {
        if (i + 1 < srcLen) {
            dest[i]     = (UCHAR)src[i + 1];
            dest[i + 1] = (UCHAR)src[i];
        } else {
            dest[i]     = ' ';
            dest[i + 1] = (UCHAR)src[i];
        }
    }
}

/* ── IRP completion context ──────────────────────────────────────── */

typedef struct _DISK_COMPLETION_CTX {
    PIO_COMPLETION_ROUTINE originalCompletion;
    PVOID                  originalContext;
    ULONG                  ioctl;
    ULONG                  propertyId;
} DISK_COMPLETION_CTX, *PDISK_COMPLETION_CTX;

/* ── Spoof StorageDeviceProperty result ──────────────────────────── */

static void SpoofDeviceProperty(PVOID outputBuf, ULONG outputLen)
{
    PSTORAGE_DEVICE_DESCRIPTOR_EX desc = (PSTORAGE_DEVICE_DESCRIPTOR_EX)outputBuf;

    /* Serial number */
    if (desc->SerialNumberOffset && desc->SerialNumberOffset < outputLen) {
        char* serial = (char*)((PUCHAR)desc + desc->SerialNumberOffset);
        SIZE_T maxLen = outputLen - desc->SerialNumberOffset;
        SIZE_T origLen = strnlen(serial, maxLen);
        if (origLen > 0 && origLen < maxLen)
            DiskReplaceString(serial, origLen, g_Spoof.diskSerial, strlen(g_Spoof.diskSerial));
    }

    /* Product ID */
    if (desc->ProductIdOffset && desc->ProductIdOffset < outputLen) {
        char* product = (char*)((PUCHAR)desc + desc->ProductIdOffset);
        SIZE_T maxLen = outputLen - desc->ProductIdOffset;
        SIZE_T origLen = strnlen(product, maxLen);
        if (origLen > 0 && origLen < maxLen)
            DiskReplaceString(product, origLen, g_Spoof.diskProductId, strlen(g_Spoof.diskProductId));
    }

    /* Vendor ID */
    if (desc->VendorIdOffset && desc->VendorIdOffset < outputLen) {
        char* vendor = (char*)((PUCHAR)desc + desc->VendorIdOffset);
        SIZE_T maxLen = outputLen - desc->VendorIdOffset;
        SIZE_T origLen = strnlen(vendor, maxLen);
        if (origLen > 0 && origLen < maxLen)
            DiskReplaceString(vendor, origLen, g_Spoof.diskVendorId, strlen(g_Spoof.diskVendorId));
    }
}

/* ── Spoof StorageDeviceIdProperty (VPD Page 83) result ──────────── */

static void SpoofDeviceIdProperty(PVOID outputBuf, ULONG outputLen)
{
    PSTORAGE_DEVICE_ID_DESCRIPTOR_EX desc = (PSTORAGE_DEVICE_ID_DESCRIPTOR_EX)outputBuf;
    if (outputLen < sizeof(STORAGE_DEVICE_ID_DESCRIPTOR_EX)) return;

    /* Walk through all identifiers and randomize them */
    PUCHAR p = desc->Identifiers;
    PUCHAR end = (PUCHAR)outputBuf + outputLen;

    for (ULONG i = 0; i < desc->NumberOfIdentifiers && p < end; i++) {
        PSTORAGE_IDENTIFIER_EX id = (PSTORAGE_IDENTIFIER_EX)p;
        if ((PUCHAR)id + sizeof(STORAGE_IDENTIFIER_EX) > end) break;
        if (id->IdentifierSize == 0) break;
        if ((PUCHAR)id->Identifier + id->IdentifierSize > end) break;

        /* Overwrite the identifier bytes with spoofed data */
        for (USHORT j = 0; j < id->IdentifierSize && j < g_Spoof.vpdPage83Len; j++)
            id->Identifier[j] = g_Spoof.vpdPage83[j];

        /* Move to next identifier */
        if (id->NextOffset == 0) break;
        p += id->NextOffset;
    }
}

/* ── Spoof StorageDeviceUniqueIdProperty result ──────────────────── */

static void SpoofDeviceUniqueId(PVOID outputBuf, ULONG outputLen)
{
    /*
     * The output is a STORAGE_DEVICE_UNIQUE_IDENTIFIER followed by
     * device ID and adapter ID blobs. We overwrite the device ID blob
     * which contains VPD identifiers.
     */
    PSTORAGE_DEVICE_UNIQUE_IDENTIFIER_EX uid =
        (PSTORAGE_DEVICE_UNIQUE_IDENTIFIER_EX)outputBuf;

    if (outputLen < sizeof(STORAGE_DEVICE_UNIQUE_IDENTIFIER_EX)) return;

    /* Spoof the device ID blob */
    if (uid->StorageDeviceIdSize > 0 && uid->StorageDeviceOffset < outputLen) {
        PUCHAR devIdBlob = (PUCHAR)outputBuf + uid->StorageDeviceOffset;
        ULONG devIdSize = uid->StorageDeviceIdSize;

        if (uid->StorageDeviceOffset + devIdSize <= outputLen) {
            /* This blob is a STORAGE_DEVICE_ID_DESCRIPTOR — spoof it */
            SpoofDeviceIdProperty(devIdBlob, devIdSize);
        }
    }
}

/* ── Spoof ATA IDENTIFY / SMART data ─────────────────────────────── */

static void SpoofAtaIdentify(PUCHAR identifyData, ULONG dataLen)
{
    if (dataLen < 512) return; /* ATA IDENTIFY is always 512 bytes */

    /* Serial number: words 10-19 (bytes 20-39), 20 chars, byte-swapped */
    DiskSetAtaString(identifyData + ATA_IDENTIFY_SERIAL_OFFSET,
        g_Spoof.diskSerial, ATA_IDENTIFY_SERIAL_LEN);

    /* Model number: words 27-46 (bytes 54-93), 40 chars, byte-swapped */
    DiskSetAtaString(identifyData + ATA_IDENTIFY_MODEL_OFFSET,
        g_Spoof.diskProductId, ATA_IDENTIFY_MODEL_LEN);

    /* Firmware revision: words 23-26 (bytes 46-53), 8 chars, byte-swapped */
    DiskSetAtaString(identifyData + ATA_IDENTIFY_FW_OFFSET,
        g_Spoof.biosVersion, ATA_IDENTIFY_FW_LEN);
}

/* ── Completion routine — spoofs results after original driver ────── */

static NTSTATUS DiskCompletionRoutine(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context)
{
    PDISK_COMPLETION_CTX ctx = (PDISK_COMPLETION_CTX)Context;

    if (Irp->IoStatus.Status == STATUS_SUCCESS && g_Spoof.initialized) {
        PVOID outputBuf = Irp->AssociatedIrp.SystemBuffer;
        ULONG outputLen = (ULONG)Irp->IoStatus.Information;

        if (outputBuf && outputLen > 0) {
            if (ctx->ioctl == IOCTL_STORAGE_QUERY_PROPERTY) {
                switch (ctx->propertyId) {
                case StorageDeviceProperty_Ex:
                    SpoofDeviceProperty(outputBuf, outputLen);
                    break;
                case StorageDeviceIdProperty_Ex:
                    SpoofDeviceIdProperty(outputBuf, outputLen);
                    break;
                case StorageDeviceUniqueIdProperty_Ex:
                    SpoofDeviceUniqueId(outputBuf, outputLen);
                    break;
                }
            }
            else if (ctx->ioctl == SMART_RCV_DRIVE_DATA) {
                /* SMART output: SENDCMDOUTPARAMS with 512-byte IDENTIFY buffer */
                SENDCMDOUTPARAMS_S* outParams = (SENDCMDOUTPARAMS_S*)outputBuf;
                if (outputLen >= sizeof(SENDCMDOUTPARAMS_S) + 511) {
                    SpoofAtaIdentify(outParams->bBuffer, outParams->cBufferSize);
                }
            }
            else if (ctx->ioctl == IOCTL_ATA_PASS_THROUGH) {
                /* ATA_PASS_THROUGH_EX: data follows the structure at DataBufferOffset */
                ATA_PASS_THROUGH_EX_S* ata = (ATA_PASS_THROUGH_EX_S*)outputBuf;
                if (outputLen > ata->DataBufferOffset + 512) {
                    PUCHAR identifyData = (PUCHAR)outputBuf + ata->DataBufferOffset;
                    SpoofAtaIdentify(identifyData, ata->DataTransferLength);
                }
            }
        }
    }

    /* Call original completion routine if present */
    NTSTATUS status = STATUS_SUCCESS;
    if (ctx->originalCompletion) {
        status = ctx->originalCompletion(DeviceObject, Irp, ctx->originalContext);
    }

    ExFreePoolWithTag(ctx, 'kDpS');

    if (status == STATUS_MORE_PROCESSING_REQUIRED)
        return STATUS_MORE_PROCESSING_REQUIRED;

    return STATUS_SUCCESS;
}

/* ── Install completion routine helper ───────────────────────────── */

static BOOLEAN InstallDiskCompletion(PIO_STACK_LOCATION ioStack, ULONG ioctl, ULONG propId)
{
    PDISK_COMPLETION_CTX ctx = (PDISK_COMPLETION_CTX)
        ExAllocatePoolWithTag(NonPagedPool, sizeof(DISK_COMPLETION_CTX), 'kDpS');
    if (!ctx) return FALSE;

    ctx->ioctl = ioctl;
    ctx->propertyId = propId;
    ctx->originalCompletion = ioStack->CompletionRoutine;
    ctx->originalContext = ioStack->Context;

    ioStack->CompletionRoutine = DiskCompletionRoutine;
    ioStack->Context = ctx;
    ioStack->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
    return TRUE;
}

/* ── Hooked IRP_MJ_DEVICE_CONTROL dispatch ───────────────────────── */

static NTSTATUS HookedDiskDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    PDRIVER_DISPATCH originalDispatch = NULL;

    /* Find the original dispatch for this driver */
    for (int i = 0; i < MAX_DISK_HOOKS; i++) {
        if (g_DiskHooks[i].active &&
            g_DiskHooks[i].driverObject == DeviceObject->DriverObject)
        {
            originalDispatch = g_DiskHooks[i].originalDispatch;
            break;
        }
    }

    if (!originalDispatch) {
        Irp->IoStatus.Status = STATUS_INTERNAL_ERROR;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INTERNAL_ERROR;
    }

    ULONG ioctl = ioStack->Parameters.DeviceIoControl.IoControlCode;

    if (ioctl == IOCTL_STORAGE_QUERY_PROPERTY) {
        PSTORAGE_PROPERTY_QUERY_EX query =
            (PSTORAGE_PROPERTY_QUERY_EX)Irp->AssociatedIrp.SystemBuffer;

        if (query &&
            ioStack->Parameters.DeviceIoControl.InputBufferLength >=
                sizeof(STORAGE_PROPERTY_QUERY_EX) &&
            query->QueryType == PropertyStandardQuery_Ex)
        {
            ULONG propId = query->PropertyId;

            /* Intercept all property types that contain serial/ID info */
            if (propId == StorageDeviceProperty_Ex ||
                propId == StorageDeviceIdProperty_Ex ||
                propId == StorageDeviceUniqueIdProperty_Ex)
            {
                InstallDiskCompletion(ioStack, ioctl, propId);
            }
        }
    }
    else if (ioctl == SMART_RCV_DRIVE_DATA) {
        /* SMART IDENTIFY — contains ATA serial, model, firmware */
        InstallDiskCompletion(ioStack, ioctl, 0);
    }
    else if (ioctl == IOCTL_ATA_PASS_THROUGH) {
        /* ATA passthrough — check if it's an IDENTIFY command */
        ATA_PASS_THROUGH_EX_S* ata =
            (ATA_PASS_THROUGH_EX_S*)Irp->AssociatedIrp.SystemBuffer;
        if (ata && ioStack->Parameters.DeviceIoControl.InputBufferLength >=
            sizeof(ATA_PASS_THROUGH_EX_S))
        {
            /* IDENTIFY DEVICE = command 0xEC */
            if (ata->CurrentTaskFile[6] == 0xEC) {
                InstallDiskCompletion(ioStack, ioctl, 0);
            }
        }
    }

    return originalDispatch(DeviceObject, Irp);
}

/* ── Extern for ObReferenceObjectByName (undocumented) ────────────── */

extern "C" NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID* Object);

/* ── Hook installation for disk drivers ──────────────────────────── */

static BOOLEAN HookDiskDriver(PUNICODE_STRING driverName)
{
    PDRIVER_OBJECT driverObj = NULL;
    NTSTATUS status = ObReferenceObjectByName(
        driverName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)&driverObj);

    if (!NT_SUCCESS(status) || !driverObj)
        return FALSE;

    LONG idx = InterlockedIncrement(&g_DiskHookCount) - 1;
    if (idx >= MAX_DISK_HOOKS) {
        InterlockedDecrement(&g_DiskHookCount);
        ObDereferenceObject(driverObj);
        return FALSE;
    }

    g_DiskHooks[idx].driverObject = driverObj;
    g_DiskHooks[idx].originalDispatch =
        driverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    g_DiskHooks[idx].active = TRUE;

    /* Swap dispatch pointer */
    InterlockedExchangePointer(
        (PVOID*)&driverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL],
        (PVOID)HookedDiskDeviceControl);

    ObDereferenceObject(driverObj);
    return TRUE;
}

/* ── Install all disk hooks ──────────────────────────────────────── */

static BOOLEAN InstallDiskSpoof()
{
    BOOLEAN anyHooked = FALSE;

    /* Hook disk.sys — handles most STORAGE_QUERY_PROPERTY for physical disks */
    UNICODE_STRING diskSys = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
    if (HookDiskDriver(&diskSys))
        anyHooked = TRUE;

    /* Hook storport/storahci miniports for RAID arrays */
    UNICODE_STRING storahci = RTL_CONSTANT_STRING(L"\\Driver\\storahci");
    if (HookDiskDriver(&storahci))
        anyHooked = TRUE;

    /* Hook partmgr for partition-level queries */
    UNICODE_STRING partmgr = RTL_CONSTANT_STRING(L"\\Driver\\partmgr");
    if (HookDiskDriver(&partmgr))
        anyHooked = TRUE;

    /* Hook AMD RAID driver if present (user has AMD RAID array) */
    UNICODE_STRING amdRaid = RTL_CONSTANT_STRING(L"\\Driver\\amdraid");
    if (HookDiskDriver(&amdRaid))
        anyHooked = TRUE;

    /* Also try rcraid (another AMD RAID driver name) */
    UNICODE_STRING rcRaid = RTL_CONSTANT_STRING(L"\\Driver\\rcraid");
    if (HookDiskDriver(&rcRaid))
        anyHooked = TRUE;

    return anyHooked;
}

/* ── Cleanup disk hooks ──────────────────────────────────────────── */

static void UninstallDiskSpoof()
{
    for (int i = 0; i < MAX_DISK_HOOKS; i++) {
        if (g_DiskHooks[i].active && g_DiskHooks[i].driverObject) {
            InterlockedExchangePointer(
                (PVOID*)&g_DiskHooks[i].driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
                (PVOID)g_DiskHooks[i].originalDispatch);
            g_DiskHooks[i].active = FALSE;
        }
    }
}
