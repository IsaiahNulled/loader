/*
    WebLoader — Web-based loader UI using WebView2.
    Displays a beautiful HTML interface matching the admin panel login page.
    Handles authentication, build selection, and launches the backend Loader.exe.
*/

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <wrl.h>
#include <wil/com.h>
#include <WebView2.h>
#include <WebView2EnvironmentOptions.h>

#include <string>
#include <vector>
#include <thread>
#include <functional>
#include <shlobj.h>
#include <wininet.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wininet.lib")

// ── HTML UI (written to temp file at startup) ──
#include "loader_ui.h"
static std::wstring g_htmlFilePath;

// ── Auth client (reuse from Loader) ──
#include "../Loader/self_auth.h"

using namespace Microsoft::WRL;

// ── Globals ──
static HWND                              g_hWnd = nullptr;
static ComPtr<ICoreWebView2Controller>   g_controller;
static ComPtr<ICoreWebView2>             g_webview;
static SelfAuth::api*                    g_auth = nullptr;
static std::string                       g_selectedBuild;
static std::string                       g_subExpiry = "0";
static bool                              g_dragging = false;
static POINT                             g_dragStart = {};


// ── Auth server config (must match Loader) ──
static const char* AUTH_SERVER_HOST = "73.137.88.21";
static const int   AUTH_SERVER_PORT = 7777;

// ── Window dimensions ──
static const int WIN_W = 480;
static const int WIN_H = 560;

// ── Forward declarations ──
void PostToWebView(const std::wstring& json);
void HandleWebMessage(const std::wstring& msg);
void DoAuthAsync(const std::string& key);
void DoInjectAsync(const std::string& build);
void PostToUI(const std::string& json);
std::string EscapeJsonStr(const std::string& s);

// ── Helpers ──
static std::wstring ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring ws(sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &ws[0], sz);
    return ws;
}

static std::string ToNarrow(const std::wstring& ws) {
    if (ws.empty()) return "";
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string s(sz, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], sz, nullptr, nullptr);
    return s;
}

static std::string EscapeJsonStr(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out += c;
    }
    return out;
}

// ── Enhanced Error Handling System ──
enum class WebLoaderStep {
    INITIALIZATION,
    WEBVIEW_INIT,
    AUTH_CONNECT,
    AUTH_LOGIN,
    BUILD_SELECTION,
    LAUNCH_LOADER,
    COMPLETE
};

static const char* StepToString(WebLoaderStep step) {
    switch (step) {
        case WebLoaderStep::INITIALIZATION: return "Initialization";
        case WebLoaderStep::WEBVIEW_INIT: return "WebView2 Initialization";
        case WebLoaderStep::AUTH_CONNECT: return "Auth Server Connect";
        case WebLoaderStep::AUTH_LOGIN: return "Authentication";
        case WebLoaderStep::BUILD_SELECTION: return "Build Selection";
        case WebLoaderStep::LAUNCH_LOADER: return "Launch Loader";
        case WebLoaderStep::COMPLETE: return "Complete";
        default: return "Unknown";
    }
}

static WebLoaderStep g_CurrentStep = WebLoaderStep::INITIALIZATION;
static std::string g_LastError = "";
static DWORD g_LastErrorCode = 0;

void SetCurrentStep(WebLoaderStep step) {
    g_CurrentStep = step;
    // Post step update to UI
    std::string json = "{\"type\":\"status\",\"message\":\"" + std::string(StepToString(step)) + "\"}";
    PostToUI(json);
}

void ReportError(WebLoaderStep step, const char* operation, DWORD errorCode = GetLastError(), const char* details = nullptr) {
    g_CurrentStep = step;
    g_LastError = operation;
    g_LastErrorCode = errorCode;
    
    // Get system error message
    char errMsg[512] = "";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   errMsg, sizeof(errMsg), nullptr);
    if (strlen(errMsg) > 0) {
        // Remove trailing newlines
        char* p = errMsg + strlen(errMsg) - 1;
        while (p >= errMsg && (*p == '\r' || *p == '\n')) *p-- = '\0';
    }
    
    // Log to file for debugging
    FILE* logFile = nullptr;
    fopen_s(&logFile, "webloader_error.log", "a");
    if (logFile) {
        time_t now = time(nullptr);
        struct tm tm;
        localtime_s(&tm, &now);
        fprintf(logFile, "[%04d-%02d-%02d %02d:%02d:%02d] ERROR at step %s\n",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, StepToString(step));
        fprintf(logFile, "  Operation: %s\n", operation);
        fprintf(logFile, "  Error Code: 0x%08X (%u)\n", errorCode, errorCode);
        if (details) fprintf(logFile, "  Details: %s\n", details);
        if (strlen(errMsg) > 0) fprintf(logFile, "  System: %s\n", errMsg);
        fprintf(logFile, "\n");
        fclose(logFile);
    }
    
    // Build error message for UI
    std::string errorMsg = "Error: " + std::string(operation);
    if (details) {
        errorMsg += " - " + std::string(details);
    }
    
    // Post error to UI
    std::string json = "{\"type\":\"error\",\"message\":\"" + EscapeJsonStr(errorMsg) + "\"}";
    PostToUI(json);
}

// ── Post JSON message to WebView (must call from UI thread) ──
void PostToWebView(const std::wstring& json) {
    if (g_webview)
        g_webview->PostWebMessageAsString(json.c_str());
}

// UI-thread helper: post message via PostMessage to ensure we're on the UI thread
#define WM_WEBVIEW_MSG (WM_USER + 100)

static void PostToUI(const std::string& json) {
    // Allocate string on heap, pass via LPARAM
    std::wstring* pJson = new std::wstring(ToWide(json));
    PostMessage(g_hWnd, WM_WEBVIEW_MSG, 0, (LPARAM)pJson);
}

// ── Handle messages FROM the HTML UI ──
void HandleWebMessage(const std::wstring& msg) {
    std::string m = ToNarrow(msg);

    // Simple JSON parsing (no library needed for our protocol)
    auto extract = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\"";
        size_t pos = m.find(search);
        if (pos == std::string::npos) return "";
        pos = m.find(':', pos + search.size());
        if (pos == std::string::npos) return "";
        pos = m.find('"', pos + 1);
        if (pos == std::string::npos) return "";
        size_t end = m.find('"', pos + 1);
        if (end == std::string::npos) return "";
        return m.substr(pos + 1, end - pos - 1);
    };

    std::string action = extract("action");

    if (action == "close") {
        PostMessage(g_hWnd, WM_CLOSE, 0, 0);
    }
    else if (action == "minimize") {
        ShowWindow(g_hWnd, SW_MINIMIZE);
    }
    else if (action == "auth") {
        std::string key = extract("key");
        if (!key.empty()) {
            std::thread(DoAuthAsync, key).detach();
        }
    }
    else if (action == "select-build") {
        std::string build = extract("build");
        if (!build.empty()) {
            g_selectedBuild = build;
            std::thread(DoInjectAsync, build).detach();
        }
    }
}

// ── Authentication (runs on background thread) ──
void DoAuthAsync(const std::string& key) {
    try {
        SetCurrentStep(WebLoaderStep::AUTH_CONNECT);
        
        if (!g_auth) {
            g_auth = new SelfAuth::api(AUTH_SERVER_HOST, AUTH_SERVER_PORT);
            g_auth->init();
            if (!g_auth->response.success) {
                ReportError(WebLoaderStep::AUTH_CONNECT, "Failed to connect to auth server", GetLastError(),
                          g_auth->response.message.c_str());
                PostToUI("{\"type\":\"auth-fail\",\"message\":\"" + EscapeJsonStr(g_auth->response.message) + "\"}");
                delete g_auth; g_auth = nullptr;
                return;
            }
        }

        SetCurrentStep(WebLoaderStep::AUTH_LOGIN);
        g_auth->license(key);

        if (!g_auth->response.success) {
            ReportError(WebLoaderStep::AUTH_LOGIN, "Authentication failed", GetLastError(),
                      g_auth->response.message.c_str());
            PostToUI("{\"type\":\"auth-fail\",\"message\":\"" + EscapeJsonStr(g_auth->response.message) + "\"}");
            return;
        }

        // Get expiry for display and for passing to Loader
        std::string expiry;
        if (!g_auth->user_data.subscriptions.empty()) {
            g_subExpiry = g_auth->user_data.subscriptions[0].expiry;
            time_t exp = (time_t)_strtoui64(g_subExpiry.c_str(), nullptr, 10);
            char timeBuf[64];
            struct tm tmBuf;
            localtime_s(&tmBuf, &exp);
            strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M", &tmBuf);
            expiry = timeBuf;
        }

        PostToUI("{\"type\":\"auth-success\",\"expiry\":\"" + EscapeJsonStr(expiry) + "\"}");
    }
    catch (const std::exception& e) {
        ReportError(WebLoaderStep::AUTH_LOGIN, "Authentication exception", 0, e.what());
        PostToUI("{\"type\":\"auth-fail\",\"message\":\"Internal error during authentication\"}");
    }
    catch (...) {
        ReportError(WebLoaderStep::AUTH_LOGIN, "Unknown authentication error", 0, "Non-C++ exception");
        PostToUI("{\"type\":\"auth-fail\",\"message\":\"Unknown error during authentication\"}");
    }
}

// ── XOR payload key (must match PAYLOAD_KEY in encrypt_build.py and FrontLoader) ──
static const uint8_t g_PayloadKey[] = {
    0x7A, 0x3F, 0xB2, 0xE1, 0x5C, 0x8D, 0x4E, 0xF0,
    0x1B, 0xA9, 0x63, 0xD7, 0x2E, 0x95, 0x48, 0xC6,
    0x0F, 0x84, 0x71, 0xBA, 0x3D, 0xE8, 0x56, 0x9C,
    0x27, 0xF5, 0x6A, 0xD3, 0x1E, 0x89, 0x44, 0xB7,
};
static const size_t g_PayloadKeyLen = sizeof(g_PayloadKey);

// Custom stream cipher — S-box based, 4-round key schedule, position-dependent mixing.
// Must match custom_stream_encrypt() in encrypt_build.py and FrontLoader's StreamCrypt.
static void StreamCrypt(std::vector<uint8_t>& data) {
    // Initialize S-box
    uint8_t S[256];
    for (int x = 0; x < 256; x++) S[x] = (uint8_t)x;

    // Key scheduling — 4 rounds
    uint8_t j = 0;
    for (int rnd = 0; rnd < 4; rnd++) {
        for (int x = 0; x < 256; x++) {
            j = j + S[x] + g_PayloadKey[(x + rnd) % g_PayloadKeyLen];
            uint8_t tmp = S[x]; S[x] = S[j]; S[j] = tmp;
        }
    }

    // Generate keystream and crypt
    uint8_t ii = 0;
    j = 0;
    for (size_t n = 0; n < data.size(); n++) {
        ii = ii + 1;
        j = j + S[ii];
        uint8_t tmp = S[ii]; S[ii] = S[j]; S[j] = tmp;
        uint8_t k = S[(uint8_t)(S[ii] + S[j])];
        k ^= (uint8_t)((n * 0x9E) & 0xFF); // Position-dependent mixing
        data[n] ^= k;
    }
}

// Download a file from a URL using WinINet (returns data in buffer)
static bool DownloadFromUrl(const std::string& url, std::vector<uint8_t>& outBuf) {
    HINTERNET hInet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInet) return false;

    HINTERNET hUrl = InternetOpenUrlA(hInet, url.c_str(), nullptr, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
    if (!hUrl) { InternetCloseHandle(hInet); return false; }

    outBuf.clear();
    char buf[8192];
    DWORD bytesRead = 0;
    while (InternetReadFile(hUrl, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
        outBuf.insert(outBuf.end(), buf, buf + bytesRead);
        bytesRead = 0;
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInet);
    return !outBuf.empty();
}

// ── Download + Inject (runs on background thread) ──
void DoInjectAsync(const std::string& build) {
    try {
        SetCurrentStep(WebLoaderStep::BUILD_SELECTION);
        std::string session = g_auth->getSession();

        PostToUI("{\"type\":\"progress\",\"pct\":10,\"label\":\"Downloading Loader...\",\"status\":\"Fetching from CDN\",\"dot\":\"purple\",\"subtitle\":\"Downloading " + build + " build\"}");

        // Download XOR-encrypted Loader.exe from GitHub (same as FrontLoader)
        std::string primaryUrl = "https://raw.githubusercontent.com/IsaiahNulled/loader/main/" + build + "/Loader.exe";
        std::string fallbackUrl = "https://github.com/IsaiahNulled/loader/raw/refs/heads/main/" + build + "/Loader.exe";

        std::vector<uint8_t> loaderBuf;
        if (!DownloadFromUrl(primaryUrl, loaderBuf)) {
            ReportError(WebLoaderStep::LAUNCH_LOADER, "Primary CDN download failed", GetLastError(),
                      "Trying fallback GitHub mirror");
            PostToUI("{\"type\":\"progress\",\"pct\":15,\"label\":\"Trying fallback...\",\"status\":\"Primary CDN failed\",\"dot\":\"yellow\"}");
            if (!DownloadFromUrl(fallbackUrl, loaderBuf)) {
                ReportError(WebLoaderStep::LAUNCH_LOADER, "All download sources failed", GetLastError(),
                          "Check internet connection and firewall settings");
                PostToUI("{\"type\":\"error\",\"message\":\"Failed to download Loader. Check internet connection.\"}");
                return;
            }
        }

        SetCurrentStep(WebLoaderStep::LAUNCH_LOADER);
        PostToUI("{\"type\":\"progress\",\"pct\":50,\"label\":\"Decrypting payload...\",\"status\":\"XOR stream cipher\",\"dot\":\"yellow\"}");

        // Check if already decrypted (CDN cache can serve unencrypted)
        if (loaderBuf.size() >= 2 && loaderBuf[0] == 'M' && loaderBuf[1] == 'Z') {
            // Already valid PE, skip decrypt
        } else {
            StreamCrypt(loaderBuf);
        }

        // Verify valid PE
        if (loaderBuf.size() < 1024 || loaderBuf[0] != 'M' || loaderBuf[1] != 'Z') {
            ReportError(WebLoaderStep::LAUNCH_LOADER, "Payload integrity check failed", ERROR_INVALID_DATA,
                      "Downloaded file is corrupted or not a valid PE");
            PostToUI("{\"type\":\"error\",\"message\":\"Payload integrity check failed.\"}");
            return;
        }

        PostToUI("{\"type\":\"progress\",\"pct\":70,\"label\":\"Writing payload...\",\"status\":\"Preparing loader\",\"dot\":\"purple\"}");

        // Write to temp file with random name
        char tempDir[MAX_PATH] = {};
        if (!GetTempPathA(MAX_PATH, tempDir)) {
            ReportError(WebLoaderStep::LAUNCH_LOADER, "Failed to get temp directory", GetLastError());
            PostToUI("{\"type\":\"error\",\"message\":\"Failed to prepare loader.\"}");
            return;
        }
        
        srand((unsigned)GetTickCount64() ^ GetCurrentProcessId());
        const char* chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        std::string randName;
        for (int i = 0; i < 12; i++) randName += chars[rand() % 36];
        std::string loaderPath = std::string(tempDir) + randName + ".exe";

        HANDLE hFile = CreateFileA(loaderPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            ReportError(WebLoaderStep::LAUNCH_LOADER, "Failed to create temp loader file", GetLastError(),
                      "Check disk space and permissions");
            PostToUI("{\"type\":\"error\",\"message\":\"Failed to write loader to disk.\"}");
            return;
        }
        
        DWORD written = 0;
        if (!WriteFile(hFile, loaderBuf.data(), (DWORD)loaderBuf.size(), &written, nullptr)) {
            DWORD err = GetLastError();
            CloseHandle(hFile);
            DeleteFileA(loaderPath.c_str());
            ReportError(WebLoaderStep::LAUNCH_LOADER, "Failed to write loader data", err,
                      "Disk may be full or write permissions denied");
            PostToUI("{\"type\":\"error\",\"message\":\"Failed to write loader to disk.\"}");
            return;
        }
        CloseHandle(hFile);

        // Clear decrypted buffer from memory
        SecureZeroMemory(loaderBuf.data(), loaderBuf.size());
        loaderBuf.clear();

        PostToUI("{\"type\":\"progress\",\"pct\":85,\"label\":\"Launching...\",\"status\":\"Starting loader process\",\"dot\":\"green\"}");

        // Launch Loader.exe with --build and --session so it skips auth + build selector
        std::string cmdLine = "\"" + loaderPath + "\" --build " + build + " --session " + session + " --expiry " + g_subExpiry;

        STARTUPINFOA si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};

        BOOL ok = CreateProcessA(
            loaderPath.c_str(),
            (LPSTR)cmdLine.c_str(),
            nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW,
            nullptr, tempDir, &si, &pi
        );

        if (!ok) {
            DWORD err = GetLastError();
            DeleteFileA(loaderPath.c_str());
            ReportError(WebLoaderStep::LAUNCH_LOADER, "Failed to launch loader process", err,
                      "Antivirus may be blocking execution");
            PostToUI("{\"type\":\"error\",\"message\":\"Failed to launch loader process. (error " + std::to_string(err) + ")\"}");
            return;
        }

        CloseHandle(pi.hThread);

        PostToUI("{\"type\":\"progress\",\"pct\":95,\"label\":\"Injecting...\",\"status\":\"Driver mapping in progress\",\"dot\":\"green\"}");

        // Wait for Loader — it stays alive for heartbeat, so use a reasonable timeout
        // STILL_ACTIVE means it's running (heartbeat loop) = success
        WaitForSingleObject(pi.hProcess, 30000);

        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);

        // Clean up temp file after a delay
        Sleep(3000);
        DeleteFileA(loaderPath.c_str());

        if (exitCode == STILL_ACTIVE || exitCode == 0) {
            SetCurrentStep(WebLoaderStep::COMPLETE);
            PostToUI("{\"type\":\"progress\",\"pct\":100,\"label\":\"Complete!\",\"status\":\"Cheat is running\",\"dot\":\"green\"}");
            Sleep(800);
            PostToUI("{\"type\":\"done\"}");
        } else {
            ReportError(WebLoaderStep::LAUNCH_LOADER, "Loader process exited with error", exitCode,
                      "Loader failed during initialization or injection");
            PostToUI("{\"type\":\"error\",\"message\":\"Loader exited with error code " + std::to_string(exitCode) + "\"}");
        }
    }
    catch (const std::exception& e) {
        ReportError(WebLoaderStep::LAUNCH_LOADER, "Injection exception", 0, e.what());
        PostToUI("{\"type\":\"error\",\"message\":\"Internal error during injection\"}");
    }
    catch (...) {
        ReportError(WebLoaderStep::LAUNCH_LOADER, "Unknown injection error", 0, "Non-C++ exception");
        PostToUI("{\"type\":\"error\",\"message\":\"Unknown error during injection\"}");
    }
}

// ── Window Procedure ──
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_SIZE:
        if (g_controller) {
            RECT bounds;
            GetClientRect(hWnd, &bounds);
            g_controller->put_Bounds(bounds);
        }
        return 0;

    case WM_WEBVIEW_MSG: {
        // Process queued WebView messages on UI thread
        std::wstring* pJson = (std::wstring*)lParam;
        if (pJson && g_webview) {
            g_webview->PostWebMessageAsString(pJson->c_str());
        }
        delete pJson;
        return 0;
    }

    case WM_NCHITTEST: {
        // Allow dragging the window from anywhere (title bar emulation)
        LRESULT hit = DefWindowProcW(hWnd, msg, wParam, lParam);
        if (hit == HTCLIENT) {
            // Check if the mouse is in the top 40px (drag area)
            POINT pt = { LOWORD(lParam), HIWORD(lParam) };
            ScreenToClient(hWnd, &pt);
            if (pt.y < 40) return HTCAPTION;
        }
        return hit;
    }

    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = WIN_W;
        mmi->ptMinTrackSize.y = WIN_H;
        mmi->ptMaxTrackSize.x = WIN_W;
        mmi->ptMaxTrackSize.y = WIN_H;
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ── Create WebView2 ──
void InitWebView(HWND hWnd) {
    try {
        SetCurrentStep(WebLoaderStep::WEBVIEW_INIT);
        
        // Use a temp folder for WebView2 user data
        wchar_t tempDir[MAX_PATH];
        if (!GetTempPathW(MAX_PATH, tempDir)) {
            ReportError(WebLoaderStep::WEBVIEW_INIT, "Failed to get temp directory for WebView2", GetLastError());
            return;
        }
        std::wstring userDataDir = std::wstring(tempDir) + L"JewWareLoader";

        HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
            nullptr, userDataDir.c_str(), nullptr,
            Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
                [hWnd](HRESULT result, ICoreWebView2Environment* env) -> HRESULT {
                    if (FAILED(result) || !env) {
                        ReportError(WebLoaderStep::WEBVIEW_INIT, "WebView2 environment creation failed", result,
                                  "WebView2 runtime may not be installed");
                        return result;
                    }

                env->CreateCoreWebView2Controller(hWnd,
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [hWnd](HRESULT result, ICoreWebView2Controller* controller) -> HRESULT {
                            if (FAILED(result) || !controller) return result;

                            g_controller = controller;
                            g_controller->get_CoreWebView2(&g_webview);

                            // Settings: hide default UI, enable devtools only in debug
                            ComPtr<ICoreWebView2Settings> settings;
                            g_webview->get_Settings(&settings);
                            settings->put_IsScriptEnabled(TRUE);
                            settings->put_AreDefaultScriptDialogsEnabled(FALSE);
                            settings->put_IsStatusBarEnabled(FALSE);
                            settings->put_AreDefaultContextMenusEnabled(FALSE);
#ifdef _DEBUG
                            settings->put_AreDevToolsEnabled(TRUE);
#else
                            settings->put_AreDevToolsEnabled(FALSE);
#endif

                            // Set bounds
                            RECT bounds;
                            GetClientRect(hWnd, &bounds);
                            g_controller->put_Bounds(bounds);

                            // Make WebView background transparent
                            ComPtr<ICoreWebView2Controller2> controller2;
                            if (SUCCEEDED(g_controller.As(&controller2))) {
                                COREWEBVIEW2_COLOR bgColor = { 0, 0, 0, 0 }; // transparent
                                controller2->put_DefaultBackgroundColor(bgColor);
                            }

                            // Listen for messages from JS
                            g_webview->add_WebMessageReceived(
                                Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                                    [](ICoreWebView2* sender, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                                        wil::unique_cotaskmem_string msg;
                                        args->TryGetWebMessageAsString(&msg);
                                        if (msg.get()) {
                                            HandleWebMessage(msg.get());
                                        }
                                        return S_OK;
                                    }
                                ).Get(), nullptr);

                            // Load the HTML from temp file
                            g_webview->Navigate(g_htmlFilePath.c_str());

                            return S_OK;
                        }
                    ).Get());
                return S_OK;
            }
        ).Get());
    }
    catch (const std::exception& e) {
        ReportError(WebLoaderStep::WEBVIEW_INIT, "WebView2 initialization exception", 0, e.what());
    }
    catch (...) {
        ReportError(WebLoaderStep::WEBVIEW_INIT, "Unknown WebView2 error", 0, "Non-C++ exception");
    }
}

// ── Entry Point ──
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    try {
        SetCurrentStep(WebLoaderStep::INITIALIZATION);
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        // Write HTML UI to temp file
        wchar_t tempDir[MAX_PATH] = {};
        if (!GetTempPathW(MAX_PATH, tempDir)) {
            ReportError(WebLoaderStep::INITIALIZATION, "Failed to get temp directory", GetLastError());
            return 1;
        }
        g_htmlFilePath = std::wstring(tempDir) + L"jw_loader_ui.html";
        if (!WriteLoaderHTML(g_htmlFilePath)) {
            ReportError(WebLoaderStep::INITIALIZATION, "Failed to write UI resources", GetLastError(),
                      "Check disk space and permissions");
            MessageBoxW(nullptr, L"Failed to write UI resources.", L"Error", MB_ICONERROR);
            return 1;
        }

    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(10, 10, 15)); // Match HTML bg
    wc.lpszClassName = L"JewWareLoader";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    // Center on screen
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int x = (screenW - WIN_W) / 2;
    int y = (screenH - WIN_H) / 2;

    // Create borderless window with rounded corners
    g_hWnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        L"JewWareLoader",
        L"Jew Ware",
        WS_POPUP | WS_MINIMIZEBOX | WS_SYSMENU,
        x, y, WIN_W, WIN_H,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!g_hWnd) return 1;

    // Round corners (Windows 11+)
    enum DWMWINDOWATTRIBUTE_DWM { DWMWA_WINDOW_CORNER_PREFERENCE_DWM = 33 };
    enum DWM_WINDOW_CORNER_PREFERENCE_DWM { DWMWCP_ROUND_DWM = 2 };
    HMODULE hDwm = LoadLibraryW(L"dwmapi.dll");
    if (hDwm) {
        typedef HRESULT(WINAPI* DwmSetWindowAttributeFn)(HWND, DWORD, LPCVOID, DWORD);
        auto pDwmSetWindowAttribute = (DwmSetWindowAttributeFn)GetProcAddress(hDwm, "DwmSetWindowAttribute");
        if (pDwmSetWindowAttribute) {
            int pref = DWMWCP_ROUND_DWM;
            pDwmSetWindowAttribute(g_hWnd, DWMWA_WINDOW_CORNER_PREFERENCE_DWM, &pref, sizeof(pref));
        }
    }

    ShowWindow(g_hWnd, SW_SHOW);
    UpdateWindow(g_hWnd);

    // Initialize WebView2
    InitWebView(g_hWnd);

    // Message loop
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        if (g_auth) delete g_auth;
        CoUninitialize();
        return (int)msg.wParam;
    }
    catch (const std::exception& e) {
        ReportError(WebLoaderStep::INITIALIZATION, "WebLoader initialization exception", 0, e.what());
        MessageBoxW(nullptr, L"WebLoader failed to initialize. Check webloader_error.log for details.", L"Error", MB_ICONERROR);
        return 1;
    }
    catch (...) {
        ReportError(WebLoaderStep::INITIALIZATION, "Unknown WebLoader error", 0, "Non-C++ exception");
        MessageBoxW(nullptr, L"WebLoader encountered an unknown error. Check webloader_error.log for details.", L"Error", MB_ICONERROR);
        return 1;
    }
}
