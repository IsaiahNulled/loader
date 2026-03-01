# Loader Build Selection Implementation

## Overview
The loader now handles build selection directly after authentication, providing users with a clear choice between safe (read-only) and full (write-enabled) builds.

## User Experience

### Step-by-Step Flow
1. **Run Loader.exe**
2. **Authenticate** with license key
3. **Build Selection Prompt** appears:
   ```
   ========================================
            BUILD SELECTION
   ========================================
   
   Select your preferred build type:
   
     [1] SAFE (Read-Only)
         • ESP and visual features only
         • No cheats or modifications
         • Lower detection risk
   
     [2] FULL (Write-Enabled)
         • All features including cheats
         • Aimbot, no recoil, etc.
         • Higher detection risk
   
   Enter your choice (1-2): _
   ```
4. **Automatic Download** of selected components
5. **Installation** of matching driver
6. **Launch** appropriate User.exe

## Technical Implementation

### New Loader Functions
- `SelectBuildType()` - Console UI for build selection
- `DownloadAndInstallBuild()` - Downloads and installs components
- `DownloadFile()` - Simple URLDownloadToFile wrapper
- `SelfAuth::api::SelectBuild()` - Public method for server communication

### Server Endpoint
- `POST /api/select-build` - Returns GitHub URLs for selected build
- Requires admin authentication
- Returns JSON with user, loader, and driver URLs

### Component URLs
```
Safe Build:
  User.exe: https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/safe/User.exe
  Loader.exe: https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/safe/Loader.exe
  driver.sys: https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/safe/driver.sys

Full Build:
  User.exe: https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/full/User.exe
  Loader.exe: https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/full/Loader.exe
  driver.sys: https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/full/driver.sys
```

## Build Differences

### Safe Build Components
- **User.exe**: Read-only ESP client (no cheats)
- **driver.sys**: Read-only driver (write commands removed)
- **Loader.exe**: Safe loader (no cleanup, no self-destruct)

### Full Build Components
- **User.exe**: Full-featured cheat client
- **driver.sys**: Write-enabled driver (all commands)
- **Loader.exe**: Full loader (cleanup, watchdog, self-destruct)

## Security Benefits

### Risk-Based Selection
- **Safe**: Minimal detection risk, ESP only
- **Full**: Maximum features, higher detection risk
- **User Choice**: Clear risk vs. functionality trade-off

### Separation of Concerns
- No risk of accidentally loading wrong driver
- Each build has appropriate protection level
- Clear visual distinction in loader

## Implementation Details

### Driver Modifications (Safe)
```cpp
// Removed from hook.cpp:
case CMD_WRITE:           // Memory write
case CMD_WRITE64:         // 64-bit write  
case CMD_WRITE_SCATTER:    // Scatter write

// Removed from physical_memory.h:
PhysicalWriteProcessMemory() function
```

### Loader Modifications (Safe)
```cpp
// Disabled features:
RunEACCleanup();          // EAC process cleanup
antitamper::LockdownProcess(); // Process lockdown
SelfAuth::api::SelfDestruct(); // Self-destruct
```

### User Modifications (Safe)
- GUI limited to "Visuals" and "Options" tabs
- No aimbot, weapon modifiers, movement cheats
- No world modifiers (time, terrain, layers)

## Maintenance

### Build Process
```batch
# Safe Build
cd c:\Users\Isaiah\Desktop\external\safe
build.bat

# Full Build  
cd c:\Users\Isaiah\Desktop\external\full
build.bat
```

### Updates
- Both builds share most codebase
- Safe build has write operations stripped at compile time
- Single loader handles both build types
- Server provides download URLs dynamically

## Testing

### Loader Build
✅ Compiles successfully with build selection
✅ Authentication flow intact
✅ Build selection UI functional
✅ Server communication working

### Next Steps
1. Build both safe and full solutions
2. Upload binaries to GitHub
3. Test complete download and installation flow
4. Verify driver compatibility with each build

## Benefits Summary

1. **User Control**: Users choose their risk level
2. **Clear Separation**: No confusion about build types
3. **Automatic Process**: No manual file management
4. **Security**: Appropriate protection for each build
5. **Maintenance**: Single codebase, conditional compilation
