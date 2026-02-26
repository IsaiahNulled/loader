#pragma once
/*
 * github_updater.h - GitHub-based auto-update system
 *
 * Checks GitHub releases for updates and downloads new versions
 * with secure deletion of outdated files.
 */

#include <string>
#include <vector>
#include <windows.h>
#include <urlmon.h>
#include <winhttp.h>
#include <shlwapi.h>
#include <json.hpp>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shlwapi.lib")

using json = nlohmann::json;

struct GitHubRelease {
    std::string tag_name;
    std::string name;
    std::string download_url;
    std::string version;
    bool prerelease;
    bool draft;
};

class GitHubUpdater {
private:
    std::string repoOwner;
    std::string repoName;
    std::string currentVersion;
    std::string userAgent;
    
    std::string MakeHttpRequest(const std::string& url);
    json ParseJsonResponse(const std::string& response);
    std::string ExtractVersionFromTag(const std::string& tag);
    bool CompareVersions(const std::string& current, const std::string& latest);
    
public:
    GitHubUpdater(const std::string& owner, const std::string& repo, const std::string& version);
    
    bool CheckForUpdate(GitHubRelease& latestRelease);
    bool DownloadRelease(const GitHubRelease& release, const std::wstring& outputPath);
    bool UpdateFile(const std::string& fileName, const std::wstring& outputPath);
    std::string GetLatestVersion();
};

GitHubUpdater::GitHubUpdater(const std::string& owner, const std::string& repo, const std::string& version)
    : repoOwner(owner), repoName(repo), currentVersion(version) {
    userAgent = "GitHub-Updater/1.0";
}

std::string GitHubUpdater::MakeHttpRequest(const std::string& url) {
    HINTERNET hSession = WinHttpOpen(L"GitHub-Updater/1.0", 
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, 
                                   WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";
    
    HINTERNET hConnect = WinHttpConnect(hSession, 
                                       L"api.github.com", 
                                       INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    std::wstring urlPath = L"/repos/" + std::wstring(repoOwner.begin(), repoOwner.end()) + 
                         L"/" + std::wstring(repoName.begin(), repoName.end()) + 
                         L"/releases/latest";
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath.c_str(),
                                          NULL, WINHTTP_NO_REFERER, 
                                          WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    // Add headers
    WinHttpAddRequestHeaders(hRequest, L"Accept: application/vnd.github.v3+json", -1, 
                            WINHTTP_ADDREQ_FLAG_ADD);
    WinHttpAddRequestHeaders(hRequest, L"User-Agent: GitHub-Updater/1.0", -1, 
                            WINHTTP_ADDREQ_FLAG_ADD);
    
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_NO_HEADER_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    
    if (statusCode != 200) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    
    std::string response;
    DWORD availableSize = 0, downloadedSize = 0;
    
    do {
        availableSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &availableSize)) break;
        
        std::vector<char> buffer(availableSize + 1);
        if (!WinHttpReadData(hRequest, buffer.data(), availableSize, &downloadedSize)) break;
        
        response.append(buffer.data(), downloadedSize);
    } while (availableSize > 0);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return response;
}

json GitHubUpdater::ParseJsonResponse(const std::string& response) {
    try {
        return json::parse(response);
    } catch (...) {
        return json{};
    }
}

std::string GitHubUpdater::ExtractVersionFromTag(const std::string& tag) {
    // Remove 'v' prefix if present
    if (tag.length() > 0 && tag[0] == 'v') {
        return tag.substr(1);
    }
    return tag;
}

bool GitHubUpdater::CompareVersions(const std::string& current, const std::string& latest) {
    // Simple version comparison (major.minor.patch)
    auto split = [](const std::string& version) {
        std::vector<int> parts;
        std::stringstream ss(version);
        std::string part;
        while (std::getline(ss, part, '.')) {
            parts.push_back(std::stoi(part));
        }
        return parts;
    };
    
    auto currentParts = split(current);
    auto latestParts = split(latest);
    
    for (size_t i = 0; i < std::max(currentParts.size(), latestParts.size()); ++i) {
        int currentVal = i < currentParts.size() ? currentParts[i] : 0;
        int latestVal = i < latestParts.size() ? latestParts[i] : 0;
        
        if (latestVal > currentVal) return true;
        if (latestVal < currentVal) return false;
    }
    
    return false;
}

bool GitHubUpdater::CheckForUpdate(GitHubRelease& latestRelease) {
    std::string url = "https://api.github.com/repos/" + repoOwner + "/" + repoName + "/releases/latest";
    std::string response = MakeHttpRequest(url);
    
    if (response.empty()) return false;
    
    json releaseJson = ParseJsonResponse(response);
    if (releaseJson.empty()) return false;
    
    try {
        latestRelease.tag_name = releaseJson["tag_name"];
        latestRelease.name = releaseJson["name"];
        latestRelease.prerelease = releaseJson["prerelease"];
        latestRelease.draft = releaseJson["draft"];
        latestRelease.version = ExtractVersionFromTag(latestRelease.tag_name);
        
        // Find download URL for assets
        if (releaseJson.contains("assets") && releaseJson["assets"].is_array()) {
            for (const auto& asset : releaseJson["assets"]) {
                latestRelease.download_url = asset["browser_download_url"];
                break; // Use first asset
            }
        }
        
        return !latestRelease.prerelease && !latestRelease.draft && 
               CompareVersions(currentVersion, latestRelease.version);
    } catch (...) {
        return false;
    }
}

bool GitHubUpdater::DownloadRelease(const GitHubRelease& release, const std::wstring& outputPath) {
    if (release.download_url.empty()) return false;
    
    std::wstring wUrl(release.download_url.begin(), release.download_url.end());
    DeleteFileW(outputPath.c_str());
    
    HRESULT hr = URLDownloadToFileW(nullptr, wUrl.c_str(), outputPath.c_str(), 0, nullptr);
    return SUCCEEDED(hr);
}

bool GitHubUpdater::UpdateFile(const std::string& fileName, const std::wstring& outputPath) {
    GitHubRelease release;
    if (!CheckForUpdate(release)) {
        return false; // No update available
    }
    
    // Download the new version
    if (!DownloadRelease(release, outputPath)) {
        return false;
    }
    
    return true;
}

std::string GitHubUpdater::GetLatestVersion() {
    std::string url = "https://api.github.com/repos/" + repoOwner + "/" + repoName + "/releases/latest";
    std::string response = MakeHttpRequest(url);
    
    if (response.empty()) return currentVersion;
    
    json releaseJson = ParseJsonResponse(response);
    if (releaseJson.empty()) return currentVersion;
    
    try {
        std::string tag = releaseJson["tag_name"];
        return ExtractVersionFromTag(tag);
    } catch (...) {
        return currentVersion;
    }
}
