/*
 * FrontLoader - Build Selection & Encrypted Download
 *
 * Universal entry point. No authentication here — Loader.exe handles that.
 * Downloads are XOR-encrypted at rest on GitHub and decrypted in memory.
 */

#include <Windows.h>
#include <wininet.h>
#include <vector>
#include <string>
#include <cstdio>
#include <conio.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")

#include "skStr.h"
#include "string_crypt.h"
#include "mem_payload.h"

// ── Payload cipher key (must match PAYLOAD_KEY in encrypt_build.py) ──
static const uint8_t g_PayloadKey[] = {
    0x7A, 0x3F, 0xB2, 0xE1, 0x5C, 0x8D, 0x4E, 0xF0,
    0x1B, 0xA9, 0x63, 0xD7, 0x2E, 0x95, 0x48, 0xC6,
    0x0F, 0x84, 0x71, 0xBA, 0x3D, 0xE8, 0x56, 0x9C,
    0x27, 0xF5, 0x6A, 0xD3, 0x1E, 0x89, 0x44, 0xB7,
};
static const size_t g_PayloadKeyLen = sizeof(g_PayloadKey);

// ── GitHub URLs (encrypted strings) ─────────────────────────────────
static std::string GetLoaderUrl(const std::string& buildType) {
    // raw.githubusercontent.com is preferred — github.com/raw/ has aggressive CDN caching
    return enc::BuildUrl({E("https://"), E("raw.githubusercontent"), E(".com/"), E("IsaiahNulled"), E("/loader/"), E("main/")})
           + buildType + E("/Loader") + E(".exe");
}

static std::string GetLoaderFallbackUrl(const std::string& buildType) {
    return enc::BuildUrl({E("https://"), E("github"), E(".com/"), E("IsaiahNulled"), E("/loader/"), E("raw/refs/heads/main/")})
           + buildType + E("/Loader") + E(".exe");
}

// ── Console Helpers ─────────────────────────────────────────────────
static HANDLE hConsole = NULL;

void SetColor(int color) {
    if (hConsole) SetConsoleTextAttribute(hConsole, color);
}

void LogStatus(const char* msg) {
    SetColor(11);
    printf("[*] %s\n", msg);
    SetColor(7);
}

void LogSuccess(const char* msg) {
    SetColor(10);
    printf("[+] %s\n", msg);
    SetColor(7);
}

void LogError(const char* msg) {
    SetColor(12);
    printf("[-] %s\n", msg);
    SetColor(7);
}

void LogWarn(const char* msg) {
    SetColor(14);
    printf("[!] %s\n", msg);
    SetColor(7);
}

// ── Build Selection ─────────────────────────────────────────────────
std::string SelectBuildType() {
    printf("\n");
    SetColor(14);
    printf("  ==========================================\n");
    printf("           SELECT YOUR BUILD\n");
    printf("  ==========================================\n");
    SetColor(7);
    printf("\n");

    SetColor(10);
    printf("  [1] SAFE");
    SetColor(7);
    printf(" - Read-Only\n");
    printf("      ESP and visual features only\n");
    printf("      Lower detection risk\n");
    printf("\n");

    SetColor(12);
    printf("  [2] FULL");
    SetColor(7);
    printf(" - All Features\n");
    printf("      Aimbot, no recoil, chams, etc.\n");
    printf("      Higher detection risk\n");
    printf("\n");

    while (true) {
        SetColor(14);
        printf("  Enter choice (1 or 2): ");
        SetColor(7);

        char c = _getch();
        printf("%c\n", c);

        if (c == '1') return "safe";
        if (c == '2') return "full";

        LogError("Invalid choice. Press 1 or 2.");
    }
}

// ── Generate random temp filename ───────────────────────────────────
static std::string GenerateRandomName() {
    srand((unsigned)GetTickCount64() ^ GetCurrentProcessId());
    const char* chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string name;
    for (int i = 0; i < 12; i++)
        name += chars[rand() % 36];
    return name + E(".exe");
}

// ── Main ────────────────────────────────────────────────────────────
int main() {
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // Spoof console title
    SetConsoleTitleA(E("Service Host: Network Service").c_str());

    printf("\n");
    SetColor(15);
    printf("  ==========================================\n");
    printf("            BUILD SELECTOR\n");
    printf("  ==========================================\n");
    SetColor(7);
    printf("\n");

    // Build selection (no auth — Loader.exe handles that)
    std::string buildType = SelectBuildType();

    printf("\n");
    char msg[128];
    snprintf(msg, sizeof(msg), "Selected %s build. Downloading...",
             buildType == "safe" ? "SAFE" : "FULL");
    LogStatus(msg);

    // Download encrypted Loader.exe to memory (zero disk until decrypt)
    std::string primaryUrl = GetLoaderUrl(buildType);
    std::string fallbackUrl = GetLoaderFallbackUrl(buildType);

    LogStatus("Streaming payload to memory...");

    std::vector<uint8_t> loaderBuffer;
    if (!MemPayload::DownloadToMemoryWithFallback(primaryUrl, fallbackUrl, loaderBuffer)) {
        LogError("Failed to download loader. Check your internet connection.");
        printf("\nPress any key to exit...\n");
        _getch();
        return 1;
    }

    char sizeBuf[128];
    snprintf(sizeBuf, sizeof(sizeBuf), "Received %zu bytes (encrypted)", loaderBuffer.size());
    LogStatus(sizeBuf);

    // Check if payload needs decryption (encrypted files won't have MZ header)
    if (loaderBuffer.size() >= 2 && loaderBuffer[0] == 'M' && loaderBuffer[1] == 'Z') {
        // Already a valid PE — CDN served unencrypted cached version, skip decrypt
        LogWarn("Payload already decrypted (CDN cache), skipping cipher step");
    } else {
        // Encrypted — stream cipher decrypt
        LogStatus("Decrypting payload...");
        MemPayload::StreamCrypt(loaderBuffer, g_PayloadKey, g_PayloadKeyLen);
    }

    // Verify payload is a valid PE
    if (loaderBuffer.size() < 1024 || loaderBuffer[0] != 'M' || loaderBuffer[1] != 'Z') {
        LogError("Payload integrity check failed (invalid PE header)");
        printf("\nPress any key to exit...\n");
        _getch();
        return 1;
    }
    LogSuccess("Payload verified!");

    // Write decrypted loader to a random temp path
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string loaderPath = std::string(tempPath) + GenerateRandomName();

    HANDLE hFile = CreateFileA(loaderPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogError("Failed to prepare loader");
        printf("\nPress any key to exit...\n");
        _getch();
        return 1;
    }

    DWORD written = 0;
    WriteFile(hFile, loaderBuffer.data(), (DWORD)loaderBuffer.size(), &written, nullptr);
    CloseHandle(hFile);

    // Clear the decrypted buffer from memory immediately
    SecureZeroMemory(loaderBuffer.data(), loaderBuffer.size());
    loaderBuffer.clear();

    // Launch the loader with --build argument so it skips its own build selector
    LogStatus("Launching loader...");

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    std::string cmdLine = "\"" + loaderPath + "\" --build " + buildType;
    if (!CreateProcessA(loaderPath.c_str(), (LPSTR)cmdLine.c_str(), nullptr, nullptr, FALSE,
                        0, nullptr, tempPath, &si, &pi)) {
        LogError("Failed to launch loader");
        DeleteFileA(loaderPath.c_str());
        printf("\nPress any key to exit...\n");
        _getch();
        return 1;
    }

    LogSuccess("Loader launched!");

    // Wait briefly then clean up the temp file
    Sleep(3000);
    DeleteFileA(loaderPath.c_str());

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
