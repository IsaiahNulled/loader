#pragma once
#include <windows.h>
#include <string>

class SimpleGitHubDownloader {
private:
    std::string rawBaseUrl;

public:
    SimpleGitHubDownloader(const std::string& username, const std::string& repo, const std::string& branch, const std::string& token)
        : rawBaseUrl("https://raw.githubusercontent.com/" + username + "/" + repo + "/" + branch + "/") {
    }

    bool DownloadDriver(const std::wstring& outputPath) {
        return DownloadFile("driver/driver.sys", outputPath);
    }

    bool DownloadOverlay(const std::wstring& outputPath) {
        return DownloadFile("User/User.exe", outputPath);
    }

    bool DownloadFile(const std::string& filePath, const std::wstring& outputPath) {
        std::string fullUrl = rawBaseUrl + filePath;
        std::wstring wUrl(fullUrl.begin(), fullUrl.end());

        DeleteFileW(outputPath.c_str());

        HRESULT hr = URLDownloadToFileW(nullptr, wUrl.c_str(), outputPath.c_str(), 0, nullptr);
        if (FAILED(hr)) {
            DeleteFileW(outputPath.c_str());
            return false;
        }

        HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            DeleteFileW(outputPath.c_str());
            return false;
        }

        CloseHandle(hFile);
        return true;
    }
};
