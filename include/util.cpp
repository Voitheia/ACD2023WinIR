#include "util.hpp"
#include "logger.hpp"

std::string UserRunningProcess() {
	std::string user = "";
	int err = GetUserRunningProcess(&user);
	if (err != 0) {
		Log("[!] Unable to get user running process: " + user + " " + std::to_string(err), "util");
		user = "";
	}

	return user;
}

int GetUserRunningProcess(std::string* user) {
	HANDLE hToken{};
	std::unique_ptr<void, decltype(&CloseHandle)> uphToken(static_cast<void*>(hToken), CloseHandle);
	if (!OpenProcessToken(GetCurrentProcess(), PROCESS_ALL_ACCESS, &hToken)) {
		*user = "OpenProcessToken";
		return GetLastError();
	}

	TOKEN_USER tu;
	DWORD dwLength = 0;
	if (!GetTokenInformation(hToken, TokenUser, &tu, 0, &dwLength)) {
		*user = "GetTokenInformation";
		return GetLastError();
	}

	LPSTR name{};
	DWORD dwSize = 256;
	SID_NAME_USE SidType;
	if (!LookupAccountSidA(NULL, tu.User.Sid, name, &dwSize, NULL, &dwSize, &SidType)) {
		*user = "LookupAccountSidA";
		return GetLastError();
	}
	*user = name;

	return 0;
}