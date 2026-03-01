#pragma once
#include "definitions.h"

// Windows version detection for compatibility
typedef enum _WINDOWS_VERSION {
    WINDOWS_UNKNOWN = 0,
    WINDOWS_7 = 1,
    WINDOWS_8 = 2,
    WINDOWS_8_1 = 3,
    WINDOWS_10 = 4,
    WINDOWS_11 = 5
} WINDOWS_VERSION;

// Safe hook detection - avoid PTE hooking on problematic systems
static BOOLEAN IsPteHookSafe() {
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    
    if (NT_SUCCESS(RtlGetVersion(&versionInfo))) {
        // Disable PTE hooking on Windows 10 due to compatibility issues
        if (versionInfo.dwMajorVersion == 10 && versionInfo.dwMinorVersion == 0) {
            return FALSE; // Windows 10 - use safer method
        }
        
        // Also disable on Windows 11 for now
        if (versionInfo.dwMajorVersion >= 10 && versionInfo.dwBuildNumber >= 22000) {
            return FALSE; // Windows 11+ - use safer method
        }
    }
    
    return TRUE; // Allow on older systems (Windows 7/8/8.1)
}

// Alternative communication method for Windows 10/11
static BOOLEAN UseAlternativeComm() {
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    
    if (NT_SUCCESS(RtlGetVersion(&versionInfo))) {
        // Use alternative method on Windows 10/11
        if (versionInfo.dwMajorVersion == 10 || 
            (versionInfo.dwMajorVersion >= 10 && versionInfo.dwBuildNumber >= 22000)) {
            return TRUE;
        }
    }
    
    return FALSE;
}
