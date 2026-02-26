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
    
    printf("[Hotbar] Downloading images to: %s\n", imagesDir.c_str());
    
    int totalItems = (int)m_itemShortnames.size();
    int downloaded = 0;
    
    for (const auto& shortname : m_itemShortnames) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_running) break;
        }
        
        // Construct URL - using a placeholder for now
        // In a real implementation, you'd use a proper Rust item icon API
        std::string url = "https://rustlabs.com/img/items/" + shortname + ".png";
        std::string filePath = imagesDir + "\\" + shortname + ".png";
        
        // Skip if file already exists
        if (std::filesystem::exists(filePath)) {
            downloaded++;
            m_progress = (downloaded * 100) / totalItems;
            continue;
        }
        
        // Download file
        if (DownloadFile(url, filePath)) {
            downloaded++;
            printf("[Hotbar] Downloaded: %s (%d/%d)\n", shortname.c_str(), downloaded, totalItems);
        } else {
            // Try alternative URL pattern
            std::string altUrl = "https://files.facepunch.com/rust/item-icons/" + shortname + ".png";
            if (DownloadFile(altUrl, filePath)) {
                downloaded++;
                printf("[Hotbar] Downloaded (alt): %s (%d/%d)\n", shortname.c_str(), downloaded, totalItems);
            } else {
                printf("[Hotbar] Failed to download: %s\n", shortname.c_str());
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
        printf("[Hotbar] Download complete: %d/%d files\n", downloaded, totalItems);
    }
}

bool HotbarDownloader::DownloadFile(const std::string& url, const std::string& path) {
    HINTERNET hSession = WinHttpOpen(L"HotbarDownloader/1.0", 
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, 
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"rustlabs.com", 
                                       INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Convert URL to wide string
    std::wstring wideUrl(url.begin(), url.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wideUrl.c_str(),
                                           NULL, WINHTTP_NO_REFERER, 
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Send request
    BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
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
