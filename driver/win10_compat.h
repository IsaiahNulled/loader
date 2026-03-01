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

// Enhanced Windows 10 compatibility with safer hooking
static BOOLEAN IsWindows10OrLater() {
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    
    if (NT_SUCCESS(RtlGetVersion(&versionInfo))) {
        if (versionInfo.dwMajorVersion >= 10) {
            return TRUE;
        }
    }
    
    return FALSE;
}

// Check if we should use enhanced safety measures
static BOOLEAN UseEnhancedSafety() {
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    
    if (NT_SUCCESS(RtlGetVersion(&versionInfo))) {
        // Windows 10 1903+ (build 18362+) has stricter memory protection
        if (versionInfo.dwMajorVersion == 10 && versionInfo.dwBuildNumber >= 18362) {
            return TRUE;
        }
        
        // Windows 11 definitely needs enhanced safety
        if (versionInfo.dwMajorVersion >= 10 && versionInfo.dwBuildNumber >= 22000) {
            return TRUE;
        }
    }
    
    return FALSE;
}

// Check if PatchGuard is likely to be active (Windows 10+)
static BOOLEAN IsPatchGuardLikelyActive() {
    return IsWindows10OrLater();
}

// Determine if we should use IPI flushing (safer on newer systems)
static BOOLEAN UseSafeFlushing() {
    return UseEnhancedSafety();
}

// Check if we should avoid large page manipulation
static BOOLEAN AvoidLargePageManipulation() {
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    
    if (NT_SUCCESS(RtlGetVersion(&versionInfo))) {
        // Windows 10 2004+ (build 19041) has issues with large page splitting
        if (versionInfo.dwMajorVersion == 10 && versionInfo.dwBuildNumber >= 19041) {
            return TRUE;
        }
    }
    
    return FALSE;
}

// Check if we should completely disable PTE hooking (for problematic builds)
static BOOLEAN ShouldDisablePteHooking() {
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    
    if (NT_SUCCESS(RtlGetVersion(&versionInfo))) {
        // Windows 10 22H2 (build 19045) is causing PAGE_FAULT_IN_NONPAGED_AREA
        if (versionInfo.dwMajorVersion == 10 && versionInfo.dwBuildNumber >= 19045) {
            return TRUE; // Disable PTE hooking entirely on build 19045+
        }
        
        // Also disable on other problematic builds
        if (versionInfo.dwMajorVersion == 10 && versionInfo.dwBuildNumber >= 19041 && versionInfo.dwBuildNumber < 19042) {
            return TRUE; // Early 2004 builds
        }
    }
    
    return FALSE;
}
