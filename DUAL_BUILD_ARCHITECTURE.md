# Dual Build Architecture

## Overview
Two completely separate solutions for safety and flexibility:
- **Safe Build**: Read-only mode (ESP only, no cheats)
- **Full Build**: Write-enabled mode (all features including cheats)

## Folder Structure
```
c:\Users\Isaiah\Desktop\external\
├── safe\
│   ├── User\          (safe User.sln - read-only)
│   ├── driver\        (read-only driver - CMD_WRITE removed)
│   ├── Loader\        (safe loader - no cleanup, no watchdog, no self-destruct)
│   └── build.bat
└── full\
    ├── User\          (full User.sln - write-enabled)
    ├── driver\        (write-enabled driver - all commands)
    ├── Loader\        (full loader - cleanup, watchdog, self-destruct)
    └── build.bat
```

## Key Differences

### Safe Driver (Read-Only)
- `CMD_WRITE` case removed from `hook.cpp`
- `CMD_WRITE64` case removed from `hook.cpp`
- `CMD_WRITE_SCATTER` case removed from `hook.cpp`
- `PhysicalWriteProcessMemory` function removed from `physical_memory.h`
- Result: Driver can only read memory, cannot write

### Full Driver (Write-Enabled)
- All write commands intact (`CMD_WRITE`, `CMD_WRITE64`, `CMD_WRITE_SCATTER`)
- `PhysicalWriteProcessMemory` available
- Result: Driver can read and write memory

### Safe Loader
- EAC cleanup disabled (`RunEACCleanup` skipped)
- Process lockdown disabled (`LockdownProcess` commented out)
- Self-destruct disabled (just exits on kill command)
- Watchdog still runs but no self-destruct
- Result: Minimal interference, read-only operation

### Full Loader
- EAC cleanup enabled
- Process lockdown enabled
- Self-destruct enabled (batch file + PC restart)
- Watchdog with tamper checks
- Result: Full protection and cleanup

### Safe User (Read-Only)
- GUI: Only "Visuals" and "Options" tabs
- No aimbot, no weapon modifiers, no movement cheats
- No world modifiers (time, terrain, layers)
- Only ESP and overlay features
- Result: Pure read-only ESP client

### Full User (Write-Enabled)
- GUI: All tabs (Aimbot, Visuals, Misc, Lua, Cloud)
- All features enabled including cheats
- Result: Full-featured cheat client

## Server Integration

### New Endpoint
- `POST /api/select-build` - Returns download URLs for selected build
- Requires admin authentication
- Returns GitHub URLs for User.exe, Loader.exe, driver.sys

### Loader UI
- Build selection prompt after successful authentication
- Console-based selection with clear descriptions
- Downloads and installs components automatically

### GitHub Structure
```
https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/
├── safe/
│   ├── User.exe
│   ├── Loader.exe
│   └── driver.sys
└── full/
    ├── User.exe
    ├── Loader.exe
    └── driver.sys
```

## Build Process

### Safe Build
```batch
cd c:\Users\Isaiah\Desktop\external\safe
build.bat
```
Builds: User.exe (read-only), driver.sys (read-only), Loader.exe (safe)

### Full Build
```batch
cd c:\Users\Isaiah\Desktop\external\full
build.bat
```
Builds: User.exe (full), driver.sys (write-enabled), Loader.exe (full)

## User Flow
1. User runs Loader.exe
2. Authenticates with license key
3. **Build selection prompt appears in console**
4. User chooses Safe (read-only) or Full (write-enabled)
5. Loader automatically downloads correct components
6. Loader installs matching driver and launches User.exe

## Security Benefits
- **Safe Build**: Cannot be detected by anti-cheat write detection
- **Full Build**: All features but higher detection risk
- **Separation**: No risk of accidentally loading wrong driver
- **Choice**: Users can select risk level

## Maintenance
- Both builds share most codebase
- Safe build has write operations stripped at compile time
- Updates can be applied to both builds simultaneously
- Driver modifications are minimal (just remove write cases)
