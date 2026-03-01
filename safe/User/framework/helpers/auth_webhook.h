#pragma once
/*
 * auth_webhook.h - Discord bot webhook integration
 *
 * Sends injection events, heartbeats, and logout notifications
 * to the Discord tracker bot's Flask webhook server.
 *
 * Uses WinHTTP for HTTP POST requests (non-blocking where possible).
 */

#include <string>
#include <thread>
#include <atomic>
#include <Windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

class AuthWebhook {
public:
    // Configure the webhook endpoint and credentials
    void Configure(const std::string& host, int port,
                   const std::string& secret, const std::string& key)
    {
        m_Host = host;
        m_Port = port;
        m_Secret = secret;
        m_Key = key;
        m_HWID = GetMachineHWID();
    }

    // Notify the bot that injection was successful
    // Returns true if the server accepted the key
    bool NotifyInjection(const std::string& version = "1.0.0")
    {
        std::string body =
            "{\"secret\":\"" + m_Secret + "\","
            "\"key\":\"" + m_Key + "\","
            "\"hwid\":\"" + m_HWID + "\","
            "\"version\":\"" + version + "\"}";

        std::string response;
        int status = PostJSON("/api/inject", body, response);
        return (status == 200);
    }

    // Start periodic heartbeat in background thread
    void StartHeartbeat(int intervalSeconds = 60)
    {
        if (m_HeartbeatRunning) return;
        m_HeartbeatRunning = true;
        m_HeartbeatInterval = intervalSeconds;
        m_HeartbeatThread = std::thread([this]() {
            while (m_HeartbeatRunning) {
                for (int i = 0; i < m_HeartbeatInterval * 10 && m_HeartbeatRunning; i++)
                    Sleep(100);

                if (!m_HeartbeatRunning) break;

                std::string body =
                    "{\"secret\":\"" + m_Secret + "\","
                    "\"key\":\"" + m_Key + "\"}";
                std::string response;
                int status = PostJSON("/api/heartbeat", body, response);

                if (status == 410) {
                    // Session expired on server side
                    m_SessionValid = false;
                }
            }
        });
    }

    // Notify clean shutdown
    void NotifyLogout()
    {
        m_HeartbeatRunning = false;
        if (m_HeartbeatThread.joinable())
            m_HeartbeatThread.join();

        std::string body =
            "{\"secret\":\"" + m_Secret + "\","
            "\"key\":\"" + m_Key + "\"}";
        std::string response;
        PostJSON("/api/logout", body, response);
    }

    bool IsSessionValid() const { return m_SessionValid; }

private:
    std::string m_Host;
    int m_Port = 5000;
    std::string m_Secret;
    std::string m_Key;
    std::string m_HWID;
    std::atomic<bool> m_HeartbeatRunning{ false };
    std::atomic<bool> m_SessionValid{ true };
    int m_HeartbeatInterval = 60;
    std::thread m_HeartbeatThread;

    // Simple HWID from machine GUID
    static std::string GetMachineHWID()
    {
        HKEY hKey;
        char value[256] = {};
        DWORD size = sizeof(value);

        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            RegQueryValueExA(hKey, "MachineGuid", NULL, NULL,
                (LPBYTE)value, &size);
            RegCloseKey(hKey);
        }

        return std::string(value);
    }

    // HTTP POST with JSON body using WinHTTP
    int PostJSON(const std::string& path, const std::string& body,
                 std::string& responseOut)
    {
        int statusCode = 0;

        std::wstring wHost(m_Host.begin(), m_Host.end());
        std::wstring wPath(path.begin(), path.end());

        HINTERNET hSession = WinHttpOpen(L"AuthClient/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return 0;

        HINTERNET hConnect = WinHttpConnect(hSession,
            wHost.c_str(), (INTERNET_PORT)m_Port, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return 0;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect,
            L"POST", wPath.c_str(), NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return 0;
        }

        // Set timeouts (5 second connect, 10 second send/receive)
        WinHttpSetTimeouts(hRequest, 5000, 5000, 10000, 10000);

        LPCWSTR contentType = L"Content-Type: application/json\r\n";
        BOOL sent = WinHttpSendRequest(hRequest,
            contentType, -1L,
            (LPVOID)body.c_str(), (DWORD)body.size(),
            (DWORD)body.size(), 0);

        if (sent && WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD dwStatus = 0;
            DWORD dwSize = sizeof(dwStatus);
            WinHttpQueryHeaders(hRequest,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &dwStatus, &dwSize, WINHTTP_NO_HEADER_INDEX);
            statusCode = (int)dwStatus;

            // Read response body
            DWORD bytesAvail = 0;
            while (WinHttpQueryDataAvailable(hRequest, &bytesAvail) && bytesAvail > 0) {
                char buf[1024];
                DWORD bytesRead = 0;
                DWORD toRead = min(bytesAvail, (DWORD)sizeof(buf) - 1);
                if (WinHttpReadData(hRequest, buf, toRead, &bytesRead)) {
                    buf[bytesRead] = '\0';
                    responseOut += buf;
                }
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return statusCode;
    }
};

// Global instance
inline AuthWebhook g_AuthWebhook;
