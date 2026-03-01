#pragma once
/*
 * crash_log.h - Lightweight crash logger for diagnosing game crashes.
 *
 * Usage:
 *   CrashLog::Init();                      // Call once at startup
 *   CLOG("message %d", value);             // Log a line (auto-flushed)
 *   CLOG_CONTEXT("FillPlayerCache");       // Set current context (shown on crash)
 *
 * On unhandled exception, writes crash details (RIP, exception code, context)
 * to the log file before the process dies.
 *
 * Log file: crash_log.txt on the user's Desktop, capped at ~500KB.
 */

#include <windows.h>
#include <ShlObj.h>
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <atomic>
#include <mutex>

namespace CrashLog {

inline FILE*        g_File = nullptr;
inline std::mutex   g_Mutex;
inline char         g_Context[256] = "init";
inline char         g_LogPath[MAX_PATH] = {};
inline std::atomic<int> g_LineCount{0};

// Max lines before truncating (keeps ~last 500KB)
constexpr int MAX_LINES = 10000;

inline void Init() {
    char desktop[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, 0, desktop)))
        sprintf_s(g_LogPath, "%s\\crash_log.txt", desktop);
    else
        sprintf_s(g_LogPath, "C:\\crash_log.txt"); // fallback

    g_File = fopen(g_LogPath, "a");
    if (g_File) {
        // Separator for new session
        time_t now = time(nullptr);
        struct tm t;
        localtime_s(&t, &now);
        fprintf(g_File, "\n===== SESSION %04d-%02d-%02d %02d:%02d:%02d =====\n",
            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec);
        fflush(g_File);
    }
}

inline void Log(const char* fmt, ...) {
    if (!g_File) return;
    std::lock_guard<std::mutex> lk(g_Mutex);

    // Truncate if too large
    if (g_LineCount.fetch_add(1) > MAX_LINES) {
        fclose(g_File);
        g_File = fopen(g_LogPath, "w"); // Truncate
        g_LineCount = 0;
        if (!g_File) return;
        fprintf(g_File, "--- LOG TRUNCATED ---\n");
    }

    // Timestamp
    ULONGLONG tick = GetTickCount64();
    unsigned sec = (unsigned)(tick / 1000) % 100000;
    unsigned ms  = (unsigned)(tick % 1000);
    fprintf(g_File, "[%05u.%03u] ", sec, ms);

    va_list args;
    va_start(args, fmt);
    vfprintf(g_File, fmt, args);
    va_end(args);

    fprintf(g_File, "\n");
    fflush(g_File); // Critical: flush every line so it survives crashes
}

inline void SetContext(const char* ctx) {
    strncpy_s(g_Context, ctx, _TRUNCATE);
}

// Unhandled exception filter — writes crash info before death
inline LONG WINAPI CrashFilter(PEXCEPTION_POINTERS ex) {
    if (!g_File) {
        // Try to open as last resort
        g_File = fopen(g_LogPath, "a");
    }
    if (g_File) {
        fprintf(g_File, "\n!!! CRASH DETECTED !!!\n");
        fprintf(g_File, "Context: %s\n", g_Context);
        if (ex && ex->ExceptionRecord) {
            fprintf(g_File, "Exception: 0x%08X\n", ex->ExceptionRecord->ExceptionCode);
            fprintf(g_File, "Address:   0x%p\n", ex->ExceptionRecord->ExceptionAddress);
            fprintf(g_File, "Flags:     0x%08X\n", ex->ExceptionRecord->ExceptionFlags);
            if (ex->ExceptionRecord->NumberParameters > 0) {
                fprintf(g_File, "Params:    ");
                for (DWORD i = 0; i < ex->ExceptionRecord->NumberParameters && i < 4; i++)
                    fprintf(g_File, "0x%llX ", ex->ExceptionRecord->ExceptionInformation[i]);
                fprintf(g_File, "\n");
            }
        }
        if (ex && ex->ContextRecord) {
            CONTEXT* c = ex->ContextRecord;
            fprintf(g_File, "RIP: 0x%016llX  RSP: 0x%016llX\n", c->Rip, c->Rsp);
            fprintf(g_File, "RAX: 0x%016llX  RBX: 0x%016llX\n", c->Rax, c->Rbx);
            fprintf(g_File, "RCX: 0x%016llX  RDX: 0x%016llX\n", c->Rcx, c->Rdx);
            fprintf(g_File, "RSI: 0x%016llX  RDI: 0x%016llX\n", c->Rsi, c->Rdi);
            fprintf(g_File, "R8:  0x%016llX  R9:  0x%016llX\n", c->R8, c->R9);
            fprintf(g_File, "R10: 0x%016llX  R11: 0x%016llX\n", c->R10, c->R11);
            fprintf(g_File, "R12: 0x%016llX  R13: 0x%016llX\n", c->R12, c->R13);
            fprintf(g_File, "R14: 0x%016llX  R15: 0x%016llX\n", c->R14, c->R15);
        }
        fprintf(g_File, "!!! END CRASH REPORT !!!\n");
        fflush(g_File);
        fclose(g_File);
        g_File = nullptr;
    }
    return EXCEPTION_CONTINUE_SEARCH; // Let Windows handle it too (create minidump)
}

inline void InstallCrashHandler() {
    SetUnhandledExceptionFilter(CrashFilter);
}

inline void Shutdown() {
    std::lock_guard<std::mutex> lk(g_Mutex);
    if (g_File) {
        fprintf(g_File, "[*] Clean shutdown\n");
        fflush(g_File);
        fclose(g_File);
        g_File = nullptr;
    }
}

} // namespace CrashLog

// Convenience macros
#define CLOG(fmt, ...)         CrashLog::Log(fmt, ##__VA_ARGS__)
#define CLOG_CONTEXT(ctx)      CrashLog::SetContext(ctx)
