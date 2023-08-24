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
	std::fstream file;
	file.open("C:\\Users\\NineBall\\Desktop\\notmypasswords.txt", std::ios::in);
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
	PHANDLE phToken{};
	for(std::string s : passList) {
		std::cout << "\"" << s << "\"" << std::endl;
		if (LogonUserA( // throwing access violation
			"NineBall",
			".",
			s.c_str(),
			LOGON32_LOGON_NEW_CREDENTIALS,
			LOGON32_PROVIDER_DEFAULT,
			phToken
		)) {
			pass = s;
		}
	}


}