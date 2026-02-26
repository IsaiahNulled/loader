#pragma once
/*
 * spoofer_utils.h - Random serial/string generation for HWID spoofing
 *
 * Uses KeQueryPerformanceCounter as entropy source (no CNG dependency).
 * All generated serials are deterministic per-boot via a seed.
 */

#include "definitions.h"

/* ── Simple PRNG (xorshift64) ────────────────────────────────────── */

static ULONG64 g_SpoofSeed = 0;

static void SpoofSeedInit()
{
    LARGE_INTEGER time;
    LARGE_INTEGER perf = KeQueryPerformanceCounter(NULL);
    KeQuerySystemTime(&time);
    g_SpoofSeed = perf.QuadPart ^ time.QuadPart ^ (ULONG64)PsGetCurrentProcessId();
    if (!g_SpoofSeed) g_SpoofSeed = 0xDEADBEEFCAFEULL;
}

static ULONG64 SpoofRand64()
{
    g_SpoofSeed ^= g_SpoofSeed << 13;
    g_SpoofSeed ^= g_SpoofSeed >> 7;
    g_SpoofSeed ^= g_SpoofSeed << 17;
    return g_SpoofSeed;
}

static ULONG SpoofRand32()
{
    return (ULONG)(SpoofRand64() & 0xFFFFFFFF);
}

static UCHAR SpoofRandByte()
{
    return (UCHAR)(SpoofRand64() & 0xFF);
}

/* ── Random string generators ────────────────────────────────────── */

static void SpoofRandomHex(char* buf, int len)
{
    const char hex[] = "0123456789ABCDEF";
    for (int i = 0; i < len; i++)
        buf[i] = hex[SpoofRandByte() % 16];
    buf[len] = '\0';
}

static void SpoofRandomAlphaNum(char* buf, int len)
{
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (int i = 0; i < len; i++)
        buf[i] = charset[SpoofRandByte() % 36];
    buf[len] = '\0';
}

static void SpoofRandomSerial(char* buf, int len)
{
    const char charset[] = "0123456789abcdef";
    for (int i = 0; i < len; i++)
        buf[i] = charset[SpoofRandByte() % 16];
    buf[len] = '\0';
}

static void SpoofRandomMac(UCHAR* mac)
{
    for (int i = 0; i < 6; i++)
        mac[i] = SpoofRandByte();
    mac[0] &= 0xFE; /* clear multicast bit */
    mac[0] |= 0x02; /* set locally administered bit */
}

static void SpoofRandomGuid(char* buf)
{
    /* Format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} */
    char hex[33];
    SpoofRandomHex(hex, 32);
    RtlStringCchPrintfA(buf, 39,
        "{%c%c%c%c%c%c%c%c-%c%c%c%c-%c%c%c%c-%c%c%c%c-%c%c%c%c%c%c%c%c%c%c%c%c}",
        hex[0],hex[1],hex[2],hex[3],hex[4],hex[5],hex[6],hex[7],
        hex[8],hex[9],hex[10],hex[11],
        hex[12],hex[13],hex[14],hex[15],
        hex[16],hex[17],hex[18],hex[19],
        hex[20],hex[21],hex[22],hex[23],hex[24],hex[25],hex[26],hex[27],hex[28],hex[29],hex[30],hex[31]);
}

static void SpoofRandomUuid(UCHAR* uuid)
{
    for (int i = 0; i < 16; i++)
        uuid[i] = SpoofRandByte();
    uuid[6] = (uuid[6] & 0x0F) | 0x40; /* version 4 */
    uuid[8] = (uuid[8] & 0x3F) | 0x80; /* variant 1 */
}

/* ── Spoofed serial storage ──────────────────────────────────────── */

typedef struct _SPOOF_DATA {
    BOOLEAN initialized;

    /* Disk */
    char    diskSerial[21];        /* primary disk serial */
    char    diskSerial2[21];       /* secondary serial (RAID member) */
    char    diskProductId[24];     /* disk product/model string */
    char    diskVendorId[12];      /* disk vendor string */

    /* Volume */
    ULONG   volumeSerial;          /* NTFS/FAT volume serial (C: drive) */

    /* Baseboard */
    char    baseboardSerial[21];
    char    baseboardProduct[32];

    /* BIOS */
    char    biosSerial[21];
    char    biosVersion[16];

    /* System */
    UCHAR   systemUuid[16];
    char    systemSerial[21];      /* computersystemproduct.IdentifyingNumber */

    /* MAC */
    UCHAR   macAddress[6];

    /* Volume / GUID */
    char    diskGuid[40];          /* physicaldisk.UniqueId */

    /* Computer name */
    char    computerName[16];

    /* VPD Page 83 identifiers (SCSI/RAID) */
    UCHAR   vpdPage83[32];
    ULONG   vpdPage83Len;

    /* SMBIOS raw spoof strings for firmware table hook */
    char    smbiosSystemManuf[32];
    char    smbiosSystemProduct[32];
    char    smbiosBoardManuf[32];

    /* Boot environment */
    UCHAR   bootId[16];            /* EFI boot GUID */

    /* Monitor */
    UCHAR   edidSerial[4];         /* EDID serial bytes */

} SPOOF_DATA;

static SPOOF_DATA g_Spoof = { 0 };

static void InitSpoofData()
{
    if (g_Spoof.initialized) return;

    SpoofSeedInit();

    /* Disk serials */
    SpoofRandomSerial(g_Spoof.diskSerial, 16);
    SpoofRandomSerial(g_Spoof.diskSerial2, 16);
    SpoofRandomAlphaNum(g_Spoof.diskProductId, 16);
    SpoofRandomAlphaNum(g_Spoof.diskVendorId, 8);

    /* Volume serial — random 32-bit */
    g_Spoof.volumeSerial = SpoofRand32();

    /* Baseboard */
    SpoofRandomAlphaNum(g_Spoof.baseboardSerial, 18);
    RtlStringCchCopyA(g_Spoof.baseboardProduct, sizeof(g_Spoof.baseboardProduct),
        "Base Board");

    /* BIOS */
    SpoofRandomAlphaNum(g_Spoof.biosSerial, 16);
    SpoofRandomHex(g_Spoof.biosVersion, 4);

    /* System */
    SpoofRandomUuid(g_Spoof.systemUuid);
    SpoofRandomAlphaNum(g_Spoof.systemSerial, 16);

    /* MAC */
    SpoofRandomMac(g_Spoof.macAddress);

    /* Disk GUID / UniqueId */
    SpoofRandomGuid(g_Spoof.diskGuid);

    /* VPD Page 83 — NAA format identifier (8 bytes) */
    g_Spoof.vpdPage83Len = 8;
    for (ULONG i = 0; i < g_Spoof.vpdPage83Len; i++)
        g_Spoof.vpdPage83[i] = SpoofRandByte();
    g_Spoof.vpdPage83[0] = 0x60; /* NAA=6 (IEEE Registered Extended) */

    /* Computer name: DESKTOP-XXXXXXX */
    char suffix[8];
    SpoofRandomAlphaNum(suffix, 7);
    RtlStringCchPrintfA(g_Spoof.computerName, sizeof(g_Spoof.computerName),
        "DESKTOP-%s", suffix);

    /* SMBIOS manufacturer strings */
    RtlStringCchCopyA(g_Spoof.smbiosSystemManuf, sizeof(g_Spoof.smbiosSystemManuf),
        "System manufacturer");
    RtlStringCchCopyA(g_Spoof.smbiosSystemProduct, sizeof(g_Spoof.smbiosSystemProduct),
        "System Product Name");
    RtlStringCchCopyA(g_Spoof.smbiosBoardManuf, sizeof(g_Spoof.smbiosBoardManuf),
        "ASUSTeK COMPUTER INC.");

    /* Boot environment GUID */
    SpoofRandomUuid(g_Spoof.bootId);

    /* Monitor EDID serial */
    for (int i = 0; i < 4; i++)
        g_Spoof.edidSerial[i] = SpoofRandByte();

    g_Spoof.initialized = TRUE;
}
