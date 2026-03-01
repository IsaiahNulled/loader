#pragma once

/*
 * shared.h - Shared definitions between kernel driver and usermode client
 *
 * This header is included by both the kernel driver (hook.cpp) and
 * the usermode test client (client.cpp). Uses only C-compatible types.
 */

/* ── Command IDs ─────────────────────────────────────────────────── */

typedef enum _DRIVER_COMMAND {
    CMD_NONE = 0,
    CMD_READ = 1,
    CMD_WRITE = 2,
    CMD_MODULE_BASE = 3,
    CMD_ALLOC = 4,
    CMD_FREE = 5,
    CMD_PROTECT = 6,
    CMD_READ64 = 7,
    CMD_WRITE64 = 8,
    CMD_WRITE_SCATTER = 9,
    CMD_PING = 99,
    CMD_HIDE_PROCESS = 103,
    CMD_UNHIDE_PROCESS = 104,
    CMD_IS_PROCESS_HIDDEN = 105,
} DRIVER_COMMAND;

#ifdef __cplusplus
extern "C" {
#endif

/* Scatter write entry: address + 4-byte value (used by CMD_WRITE_SCATTER) */
typedef struct _SCATTER_WRITE_ENTRY {
    unsigned __int64 address;   /* target virtual address */
    unsigned int     value;     /* 4-byte value to write */
    unsigned int     _pad;      /* alignment padding */
} SCATTER_WRITE_ENTRY, *PSCATTER_WRITE_ENTRY;

/* ── Request Structure ───────────────────────────────────────────── */
/*
 * Passed as the first argument to NtQueryCompositionSurfaceStatistics.
 * The hooked function casts this to PREQUEST_DATA and dispatches.
 *
 * Magic must be set to REQUEST_MAGIC to distinguish our calls
 * from legitimate dxgkrnl calls.
 */

#define REQUEST_MAGIC 0x44524B4E  /* "DRKN" */

typedef struct _REQUEST_DATA {
    unsigned int    magic;          /* must be REQUEST_MAGIC               */
    unsigned int    command;        /* DRIVER_COMMAND                      */
    unsigned __int64 pid;           /* target process ID                   */
    unsigned __int64 address;       /* virtual address (for R/W)           */
    unsigned __int64 buffer;        /* usermode buffer address             */
    unsigned __int64 size;          /* bytes to R/W                        */
    unsigned __int64 result;        /* output: module base / alloc base    */
    unsigned int    protect;        /* memory protection (alloc/protect)   */
    wchar_t         module_name[64]; /* module name for CMD_MODULE_BASE    */
} REQUEST_DATA, *PREQUEST_DATA;

#ifdef __cplusplus
}
#endif
