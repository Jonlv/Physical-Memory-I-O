#include <Windows.h>
#include <winternl.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

using namespace std;

bool EnablePrivilege(
	LPCWSTR lpPrivilegeName
)
{
	TOKEN_PRIVILEGES Privilege;
	HANDLE hToken;
	DWORD dwErrorCode;

	Privilege.PrivilegeCount = 1;
	Privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValueW(NULL, lpPrivilegeName,
		&Privilege.Privileges[0].Luid))
		return GetLastError();

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES, &hToken))
		return GetLastError();

	if (!AdjustTokenPrivileges(hToken, FALSE, &Privilege, sizeof(Privilege),
		NULL, NULL)) {
		dwErrorCode = GetLastError();
		CloseHandle(hToken);
		return dwErrorCode;
	}

	CloseHandle(hToken);
	return TRUE;
}

bool create_driver_service(const std::wstring& service_name, const std::wstring& driver)
{
	std::wstring reg_key = L"System\\CurrentControlSet\\Services\\" + service_name;
	HKEY hKey;
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, reg_key.c_str(), NULL, nullptr, NULL, KEY_ALL_ACCESS, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
		
		LSTATUS err = RegSetValueExW(hKey, L"ImagePath", 0, REG_MULTI_SZ, (const BYTE*)driver.c_str(), (driver.length() + 1) * sizeof(wchar_t));
		if (err != 0) {
			::RegCloseKey(hKey);
			return false;
		}
		DWORD dwType = 1;
		err = RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (const BYTE*)&dwType, sizeof(DWORD));
		if (err != 0) {
			::RegCloseKey(hKey);
			::RegDeleteKeyEx(HKEY_LOCAL_MACHINE, reg_key.c_str(), DELETE, 0);
			return false;
		}
		DWORD dwErrorControl = 1;
		err = RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (const BYTE*)&dwErrorControl, sizeof(DWORD));
		if (err != 0) {
			::RegCloseKey(hKey);
			return false;
		}
		DWORD dwStartType = 3;
		err = RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (const BYTE*)&dwStartType, sizeof(DWORD));
		if (err != 0) {
			::RegCloseKey(hKey);
			return false;
		}
		::RegCloseKey(hKey);
		return true;
	}
	else
		return false;
}


bool load_driver(const std::wstring& service_name)
{
	std::wstring name = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + service_name;
	NTSTATUS(NTAPI *NtLoadDriver)(IN PUNICODE_STRING DriverServiceName);
	*(FARPROC *)&NtLoadDriver = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtLoadDriver");
	if (NtLoadDriver == nullptr)
		return false;
	UNICODE_STRING Path;
	RtlInitUnicodeString(&Path, name.c_str());
	return NT_SUCCESS(NtLoadDriver(&Path));
}


bool unload_driver(const std::wstring& service_name)
{
	std::wstring name = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + service_name;
	NTSTATUS(NTAPI *NtUnloadDriver)(IN PUNICODE_STRING DriverServiceName);
	*(FARPROC *)&NtUnloadDriver = GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtUnloadDriver");
	if (NtUnloadDriver == nullptr)
		return false;
	UNICODE_STRING Path;
	RtlInitUnicodeString(&Path, name.c_str());
	return NT_SUCCESS(NtUnloadDriver(&Path));
}

bool destroy_driver_service(const std::wstring& service_name)
{
	std::wstring reg_key = L"System\\CurrentControlSet\\Services\\" + service_name;
	HKEY hKey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, reg_key.c_str(), NULL, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
		RegDeleteValue(hKey, L"ImagePath");
		RegDeleteValue(hKey, L"Type");
		RegDeleteValue(hKey, L"Start");
		RegDeleteValue(hKey, L"ErrorControl");
		::RegCloseKey(hKey);
		::RegDeleteKeyEx(HKEY_LOCAL_MACHINE, reg_key.c_str(), DELETE, 0);
		return true;
	}
	else
		return true; //check GetLastError = something
}


int wmain(int argc, wchar_t* argv[])
{
	if (argc != 4) {
		cout << "loader.exe service_name system32\\file.sys options[-install,-install_load,-load,-unload, -unload_uninstall, -uninstall]" << endl;
		return -1;
	}
	if (!EnablePrivilege(L"SeLoadDriverPrivilege"))
	{
		std::cout << "[!] EnablePrivilege(\"SeLoadDriverPrivilege\") failed" << std::endl;
		return -2;
	}
	std::wstring service_name = argv[1];
	std::wstring driver = argv[2];
	std::wstring options = argv[3];
	if (options == L"-install" || options == L"-install_load") {
		if (create_driver_service(service_name, driver))
			cout << "[+] created service" << endl;
		else
			cout << "[-] failed to create service";
	}

	if (options == L"-install_load" || options == L"-load") {
		if (load_driver(service_name))
			cout << "[+] loaded driver" << endl;
		else
			cout << "[-] failed to load driver" << endl;
	}

	if (options == L"-unload" || options == L"-unload_uninstall") {
		if (unload_driver(service_name))
			cout << "[+] unloaded driver" << endl;
		else
			cout << "[-] failed to unload driver." << endl;
	}
	if (options == L"-uninstall" || options == L"-unload_uninstall") {
		if (destroy_driver_service(service_name))
			cout << "[+] destroyed service" << endl;
		else
			cout << "[-] failed to destroy service" << endl;
	}
    return 0;
}