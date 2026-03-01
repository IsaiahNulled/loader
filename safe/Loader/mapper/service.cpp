#include "service.hpp"
#include <Windows.h>
#include <string>
#include <iostream>

#include "utils.hpp"
#include "nt.hpp"

NTSTATUS service::RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName) {
	const static DWORD ServiceTypeKernel = 1;
	const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS) {
		kdmLog("[-] Can't create service key" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size()*sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		kdmLog("[-] Can't create 'ImagePath' registry value" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}
	
	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		kdmLog("[-] Can't create 'Type' registry value" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}
	
	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return STATUS_UNSUCCESSFUL;
	}

	//auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	//auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS ntStatus = nt::RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(ntStatus)) {
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		kdmLog("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator." << std::endl);
		return ntStatus;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	ntStatus = nt::NtLoadDriver(&serviceStr);

	kdmLog("[+] NtLoadDriver Status 0x" << std::hex << ntStatus << std::endl);

	if (ntStatus == STATUS_IMAGE_CERT_REVOKED || ntStatus == 0xC00000BBL /*STATUS_NOT_SUPPORTED*/ || ntStatus == 0xC0000251L /*STATUS_INVALID_IMAGE_HASH*/) {
		kdmLog("" << std::endl);
		kdmLog("[-] ===========================================================" << std::endl);
		kdmLog("[-]  Driver blocked by Windows Memory Integrity / HVCI" << std::endl);
		kdmLog("[-] ===========================================================" << std::endl);
		kdmLog("[-]  Windows 11 25H2 blocks this driver by default." << std::endl);
		kdmLog("[-]" << std::endl);
		kdmLog("[-]  To fix, do BOTH of the following:" << std::endl);
		kdmLog("[-]" << std::endl);
		kdmLog("[-]  1. Disable Memory Integrity:" << std::endl);
		kdmLog("[-]     Settings > Privacy & Security > Windows Security" << std::endl);
		kdmLog("[-]     > Device Security > Core Isolation Details" << std::endl);
		kdmLog("[-]     > Turn OFF 'Memory Integrity'" << std::endl);
		kdmLog("[-]" << std::endl);
		kdmLog("[-]  2. Disable Vulnerable Driver Blocklist:" << std::endl);
		kdmLog("[-]     Same page > Turn OFF 'Microsoft Vulnerable Driver" << std::endl);
		kdmLog("[-]     Blocklist'" << std::endl);
		kdmLog("[-]     OR set registry DWORD to 0:" << std::endl);
		kdmLog("[-]     HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config" << std::endl);
		kdmLog("[-]     VulnerableDriverBlocklistEnable = 0" << std::endl);
		kdmLog("[-]" << std::endl);
		kdmLog("[-]  Then REBOOT and try again." << std::endl);
		kdmLog("[-] ===========================================================" << std::endl);
		kdmLog("" << std::endl);
	}
	else if (ntStatus == STATUS_ACCESS_DENIED || ntStatus == STATUS_INSUFFICIENT_RESOURCES) {
		kdmLog("[-] Access Denied or Insufficient Resources (0x" << std::hex << ntStatus << "), Probably some anticheat or antivirus running blocking the load of vulnerable driver" << std::endl);
	}
	
	if (!NT_SUCCESS(ntStatus)) {
		//Remove the service
		status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		if (status != ERROR_SUCCESS) {
			kdmLog("[-] Can't delete service registry key after NtLoadDriver failure" << std::endl);
		}
	}

	return ntStatus;
}

NTSTATUS service::StopAndRemove(const std::wstring& serviceName) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return STATUS_UNSUCCESSFUL;

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND) {
			return STATUS_SUCCESS; //already removed
		}
		return STATUS_REGISTRY_IO_FAILED;
	}
	RegCloseKey(driver_service);

	NTSTATUS st = nt::NtUnloadDriver(&serviceStr);
	if (st != ERROR_SUCCESS) {
		kdmLog("[-] Driver Unload Failed!!" << std::endl);
		status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return st; //lets consider unload fail as error because can cause problems with anti cheats later
	}

	status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS) {
		return STATUS_REGISTRY_IO_FAILED;
	}
	return st;
}
