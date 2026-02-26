# HWID Spoofer - Standalone Kernel Driver

A comprehensive Windows kernel driver that spoofs hardware identifiers to evade anti-cheat HWID bans.

## Features

### Disk Spoofing
- **StorageDeviceProperty** - Serial, Product ID, Vendor ID
- **StorageDeviceIdProperty** - VPD Page 83 SCSI identifiers
- **StorageDeviceUniqueIdProperty** - `physicaldisk.UniqueId`
- **SMART/ATA IDENTIFY** - ATA serial, model, firmware (word-swapped)
- **Disk registry cache** - Enum\SCSI FriendlyName

### SMBIOS/Firmware Spoofing
- **BIOS** - Version, SerialNumber, ReleaseDate, Vendor
- **BaseBoard** - Manufacturer, Product, SerialNumber, Version
- **System** - Manufacturer, ProductName, SerialNumber, UUID
- **Registry keys** - 14+ WMI cache locations

### Network Spoofing
- **MAC addresses** - Registry NetworkAddress for all adapters
- **Computer name** - Active/Pending + TCP/IP hostname

### System Identity
- **Machine GUID** - Cryptography registry
- **Product ID** + **InstallDate** - NT\CurrentVersion
- **DigitalProductId** - 164-byte activation blob
- **HW Profile GUID** + **SQM Machine ID**

### Additional Vectors
- **Monitor EDID** - Serial bytes + checksum fix
- **Boot environment** - Firmware type markers
- **GPU IDs** - Registry enumeration

## Architecture

```
hwid-spoofer/
├── src/
│   └── main.c              # Driver entry point
├── include/
│   ├── spoofer.h           # Main orchestrator
│   ├── spoofer_utils.h     # Random generation + SPOOF_DATA
│   ├── spoofer_disk.h      # Disk serial/UniqueId/ATA spoofing
│   ├── spoofer_ntos.h      # Registry spoofs + SMBIOS
│   ├── spoofer_smbios.h    # SMBIOS table structures
│   ├── spoof_call.h        # Return address spoofing
│   └── definitions.h       # Core kernel definitions
└── HWIDSpoofer.vcxproj     # Visual Studio project
```

## Building

1. Install Windows Driver Kit (WDK)
2. Open `HWIDSpoofer.vcxproj` in Visual Studio
3. Build x64 Release configuration
4. Output: `x64\Release\HWIDSpoofer.sys`

## Usage

The driver initializes all spoofing subsystems on load:

1. **Random serial generation** - Deterministic per boot
2. **Registry identity spoofing** - Safest, always works
3. **SMBIOS/WMI registry spoof** - 14+ registry keys
4. **Boot environment spoofing** - DigitalProductId, firmware type
5. **Disk IRP hooks** - Storage IOCTL interception
6. **Disk registry cache** - Enum\SCSI FriendlyName
7. **Monitor EDID spoofing** - Binary patch + checksum
8. **GPU ID enumeration** - Optional
9. **Volume serial** - Registry portion

## Safety

- **No SEH** - Uses `MmIsAddressValid` checks (mapped driver compatible)
- **Registry-first** - Most spoofs via registry (no risky hooks)
- **Minimal IRP hooks** - Only disk driver dispatch swaps
- **No hypervisor** - Pure kernel driver, no CPUID spoofing

## Limitations

- **CPUID** - Requires hypervisor (not implemented)
- **Volume serial boot sector** - Runtime patching risky
- **UEFI variables** - Limited registry access only

## Compatibility

- Windows 10/11 x64
- Manual mapper compatible (no .pdata required)
- Works with AMD RAID arrays (amdraid/rcraid drivers)

## Notes

This is a **standalone** version extracted from a larger driver project. It contains only the HWID spoofing functionality without any game-specific features.
