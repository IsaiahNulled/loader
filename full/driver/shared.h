#pragma once

#ifdef __cplusplus
extern "C" {
#endif

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

typedef struct _SCATTER_WRITE_ENTRY {
    unsigned __int64 address;
    unsigned int     value;
    unsigned int     _pad;
} SCATTER_WRITE_ENTRY, *PSCATTER_WRITE_ENTRY;

#define REQUEST_MAGIC 0x44524B4E

typedef struct _REQUEST_DATA {
    unsigned int    magic;
    unsigned int    command;
    unsigned __int64 pid;
    unsigned __int64 address;
    unsigned __int64 buffer;
    unsigned __int64 size;
    unsigned __int64 result;
    unsigned int    protect;
    wchar_t         module_name[64];
} REQUEST_DATA, *PREQUEST_DATA;

#ifdef __cplusplus
}
#endif
