#include "hotbar_downloader.h"
#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

HotbarDownloader& HotbarDownloader::Get() {
    static HotbarDownloader instance;
    return instance;
}

HotbarDownloader::~HotbarDownloader() {
    Stop();
}

void HotbarDownloader::StartDownload() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_running) return;
    
    m_running = true;
    m_complete = false;
    m_progress = 0;
    
    m_downloadThread = std::thread(&HotbarDownloader::DownloadThread, this);
}

void HotbarDownloader::Stop() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_running = false;
    }
    
    if (m_downloadThread.joinable()) {
        m_downloadThread.join();
    }
}

bool HotbarDownloader::IsDownloadComplete() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_complete;
}

int HotbarDownloader::GetProgress() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_progress;
}

void HotbarDownloader::DownloadThread() {
    // Get temp directory
    std::string tempDir = this->GetTempDirectory();
    std::string imagesDir = tempDir + "\\rust_hotbar_images";
    
    // Create directory if it doesn't exist
    std::filesystem::create_directories(imagesDir);
    
    
    int totalItems = (int)m_itemShortnames.size();
    int downloaded = 0;
    
    for (const auto& shortname : m_itemShortnames) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_running) break;
        }
        
        // Construct URL using GitHub with proper headers
        std::string url = "https://raw.githubusercontent.com/rust-community/item-icons/main/icons/" + shortname + ".png";
        std::string filePath = imagesDir + "\\" + shortname + ".png";
        
        // Skip if file already exists
        if (std::filesystem::exists(filePath)) {
            downloaded++;
            m_progress = (downloaded * 100) / totalItems;
            continue;
        }
        
        // Download file with GitHub headers
        if (DownloadFile(url, filePath)) {
            downloaded++;
        } else {
            // Try alternative GitHub URL pattern
            std::string altUrl = "https://cdn.jsdelivr.net/gh/rust-community/item-icons@main/icons/" + shortname + ".png";
            if (DownloadFile(altUrl, filePath)) {
                downloaded++;
            } else {
            }
        }
        
        // Update progress
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_progress = (downloaded * 100) / totalItems;
        }
        
        // Small delay to avoid overwhelming servers
        Sleep(100);
    }
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_complete = true;
        m_running = false;
    }
}

bool HotbarDownloader::DownloadFile(const std::string& url, const std::string& path) {
    // Parse hostname from URL
    std::string hostname;
    if (url.find("github.com") != std::string::npos) {
        hostname = "github.com";
    } else if (url.find("cdn.jsdelivr.net") != std::string::npos) {
        hostname = "cdn.jsdelivr.net";
    } else {
        hostname = "raw.githubusercontent.com";
    }
    
    // Use generic user agent to hide download source
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, 
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    
    std::wstring wideHostname(hostname.begin(), hostname.end());
    HINTERNET hConnect = WinHttpConnect(hSession, wideHostname.c_str(), 
                                       INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Extract path from URL
    size_t hostPos = url.find(hostname);
    std::string pathOnly = url.substr(hostPos + hostname.length());
    
    // Add custom headers to hide download intent
    LPCWSTR headers = L"Accept: image/png,image/*;q=0.9,*/*;q=0.1\r\n"
                     L"Accept-Language: en-US,en;q=0.9\r\n"
                     L"Accept-Encoding: gzip, deflate, br\r\n"
                     L"DNT: 1\r\n"
                     L"Connection: keep-alive\r\n"
                     L"Sec-Fetch-Dest: image\r\n"
                     L"Sec-Fetch-Mode: no-cors\r\n"
                     L"Sec-Fetch-Site: cross-site";
    
    std::wstring widePath(pathOnly.begin(), pathOnly.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", widePath.c_str(),
                                           NULL, WINHTTP_NO_REFERER, 
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Send request with custom headers
    BOOL result = WinHttpSendRequest(hRequest, headers, -1,
                                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Receive response
    result = WinHttpReceiveResponse(hRequest, NULL);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Check status code
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, 
                       WINHTTP_NO_HEADER_INDEX);
    
    if (statusCode != 200) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Download data
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    DWORD bytesRead = 0;
    BYTE buffer[8192];
    
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        file.write((char*)buffer, bytesRead);
    }
    
    file.close();
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return true;
}

std::string HotbarDownloader::GetTempDirectory() {
    WCHAR path[MAX_PATH];
    if (::GetTempPathW(MAX_PATH, path)) {
        std::wstring ws(path);
        return std::string(ws.begin(), ws.end());
    }
    return "C:\\temp";
}

// Global instance
HotbarDownloader& g_HotbarDownloader = HotbarDownloader::Get();
