#pragma once
#include <windows.h>
#include <wininet.h>
#include <string>
#include "string_crypt.h"
#pragma comment(lib, "wininet.lib")

class SimpleGitHubDownloader {
private:
    std::string rawBaseUrl;

public:
    SimpleGitHubDownloader(const std::string& username, const std::string& repo, const std::string& branch, const std::string& token)
        : rawBaseUrl(enc::BuildUrl({E("https://"), E("github"), E(".com/")}) + username + "/" + repo + enc::BuildUrl({E("/raw/refs/heads/")}) + branch + "/") {
    }

    bool DownloadDriver(const std::wstring& outputPath) {
        return DownloadFile(E("driver/driver.sys"), outputPath);
    }

    bool DownloadOverlay(const std::wstring& outputPath) {
        return DownloadFile(E("User/User.exe"), outputPath);
    }

    bool DownloadFile(const std::string& filePath, const std::wstring& outputPath) {
        std::string fullUrl = rawBaseUrl + filePath;
        std::wstring wUrl(fullUrl.begin(), fullUrl.end());

        DeleteFileW(outputPath.c_str());

        // Delete IE cache for this URL to force fresh download
        DeleteUrlCacheEntryW(wUrl.c_str());

        HRESULT hr = URLDownloadToFileW(nullptr, wUrl.c_str(), outputPath.c_str(), 0, nullptr);
        if (FAILED(hr)) {
            // Try fallback URL format (raw.githubusercontent.com)
            std::string fallbackUrl = enc::BuildUrl({E("https://"), E("raw.githubusercontent"), E(".com/"), E("IsaiahNulled"), E("/loader/"), E("main/")}) + filePath;
            std::wstring wFallbackUrl(fallbackUrl.begin(), fallbackUrl.end());
            
            DeleteUrlCacheEntryW(wFallbackUrl.c_str());
            hr = URLDownloadToFileW(nullptr, wFallbackUrl.c_str(), outputPath.c_str(), 0, nullptr);
            
            if (FAILED(hr)) {
                DeleteFileW(outputPath.c_str());
                return false;
            }
        }

        // Verify file exists and has reasonable size (at least 10KB for exe/sys)
        HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            // File creation failed after download
            DeleteFileW(outputPath.c_str());
            return false;
        }

        LARGE_INTEGER fileSize;
        GetFileSizeEx(hFile, &fileSize);
        CloseHandle(hFile);

        if (fileSize.QuadPart < 10240) {
            // Downloaded file too small
            DeleteFileW(outputPath.c_str());
            return false;
        }

        return true;
    }
};
