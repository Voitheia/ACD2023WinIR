#include "util.hpp"

std::string utilComponentName = "util";

std::string GetUserAndContext() {
	return RunWhoami() + " " + RunWhoamiGroups();
}

std::string RunWhoami() {
	// source: https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output

	std::string retStr = "";

	HANDLE g_hChildStd_IN_Rd = NULL;
	HANDLE g_hChildStd_IN_Wr = NULL;
	HANDLE g_hChildStd_OUT_Rd = NULL;
	HANDLE g_hChildStd_OUT_Wr = NULL;
	std::unique_ptr<void, decltype(&CloseHandle)> uphg_hChildStd_IN_Rd(static_cast<void*>(g_hChildStd_IN_Rd), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphg_hChildStd_IN_Wr(static_cast<void*>(g_hChildStd_IN_Wr), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphg_hChildStd_OUT_Rd(static_cast<void*>(g_hChildStd_OUT_Rd), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphg_hChildStd_OUT_Wr(static_cast<void*>(g_hChildStd_OUT_Wr), CloseHandle);

	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
		Log("[!] RunWhoami StdoutRd CreatePipe: " + std::to_string(GetLastError()), utilComponentName);
	
	if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
		Log("[!] RunWhoami Stdout SetHandleInformation: " + std::to_string(GetLastError()), utilComponentName);

	if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
		Log("[!] RunWhoami Stdin CreatePipe: " + std::to_string(GetLastError()), utilComponentName);

	if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
		Log("[!] RunWhoami Stdin SetHandleInformation: " + std::to_string(GetLastError()), utilComponentName);

	PROCESS_INFORMATION piProcInfo;
	STARTUPINFOW siStartInfo;
	BOOL bSuccess = FALSE;

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = g_hChildStd_OUT_Wr;
	siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
	siStartInfo.hStdInput = g_hChildStd_IN_Rd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	std::unique_ptr<void, decltype(&CloseHandle)> uphProcess(static_cast<void*>(piProcInfo.hProcess), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphThread(static_cast<void*>(piProcInfo.hThread), CloseHandle);


	std::wstring cmdline = L"cmd.exe /c whoami";

	bSuccess = CreateProcessW(
		NULL,
		const_cast<LPWSTR>(cmdline.c_str()),
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&siStartInfo,
		&piProcInfo
	);

	if (!bSuccess) {
		Log("[!] RunWhoami CreateProcessW: " + std::to_string(GetLastError()), utilComponentName);
	}
	else {
		CloseHandle(piProcInfo.hProcess);
		CloseHandle(piProcInfo.hThread);
		CloseHandle(g_hChildStd_OUT_Wr);
		CloseHandle(g_hChildStd_IN_Rd);
		Log("[+] Successfully created RunWhoami powershell process.", utilComponentName);
	}

	Sleep(500);

	DWORD dwRead, dwWritten;
	CHAR chBuf[4096];

	for (;;)
	{
		bSuccess = ReadFile(g_hChildStd_OUT_Rd, chBuf, 4096, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) break;
	}

	retStr = std::string(chBuf);

	CloseHandle(g_hChildStd_IN_Wr);
	CloseHandle(g_hChildStd_OUT_Rd);

	return retStr;
}

std::string RunWhoamiGroups() {
	// source: https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output

	std::string retStr = "";

	HANDLE g_hChildStd_IN_Rd = NULL;
	HANDLE g_hChildStd_IN_Wr = NULL;
	HANDLE g_hChildStd_OUT_Rd = NULL;
	HANDLE g_hChildStd_OUT_Wr = NULL;
	std::unique_ptr<void, decltype(&CloseHandle)> uphg_hChildStd_IN_Rd(static_cast<void*>(g_hChildStd_IN_Rd), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphg_hChildStd_IN_Wr(static_cast<void*>(g_hChildStd_IN_Wr), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphg_hChildStd_OUT_Rd(static_cast<void*>(g_hChildStd_OUT_Rd), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphg_hChildStd_OUT_Wr(static_cast<void*>(g_hChildStd_OUT_Wr), CloseHandle);

	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
		Log("[!] RunWhoamiGroups StdoutRd CreatePipe: " + std::to_string(GetLastError()), utilComponentName);

	if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
		Log("[!] RunWhoamiGroups Stdout SetHandleInformation: " + std::to_string(GetLastError()), utilComponentName);

	if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
		Log("[!] RunWhoamiGroups Stdin CreatePipe: " + std::to_string(GetLastError()), utilComponentName);

	if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
		Log("[!] RunWhoamiGroups Stdin SetHandleInformation: " + std::to_string(GetLastError()), utilComponentName);

	PROCESS_INFORMATION piProcInfo;
	STARTUPINFOW siStartInfo;
	BOOL bSuccess = FALSE;

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = g_hChildStd_OUT_Wr;
	siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
	siStartInfo.hStdInput = g_hChildStd_IN_Rd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	std::unique_ptr<void, decltype(&CloseHandle)> uphProcess(static_cast<void*>(piProcInfo.hProcess), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphThread(static_cast<void*>(piProcInfo.hThread), CloseHandle);


	std::wstring cmdline = L"cmd.exe /c whoami /groups";

	bSuccess = CreateProcessW(
		NULL,
		const_cast<LPWSTR>(cmdline.c_str()),
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&siStartInfo,
		&piProcInfo
	);

	if (!bSuccess) {
		Log("[!] RunWhoami CreateProcessW: " + std::to_string(GetLastError()), utilComponentName);
	}
	else {
		CloseHandle(piProcInfo.hProcess);
		CloseHandle(piProcInfo.hThread);
		CloseHandle(g_hChildStd_OUT_Wr);
		CloseHandle(g_hChildStd_IN_Rd);
		Log("[+] Successfully created RunWhoami powershell process.", utilComponentName);
	}

	Sleep(500);

	DWORD dwRead, dwWritten;
	CHAR chBuf[4096];

	for (;;)
	{
		bSuccess = ReadFile(g_hChildStd_OUT_Rd, chBuf, 4096, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) break;
	}

	retStr = std::string(chBuf);

	//size_t pos = retStr.find("Mandatory Label\\");
	//if (pos == std::string::npos) {
	//	Log("[!] Error extracting context", utilComponentName);
	//	return retStr;
	//}

	//std::string context = retStr.substr(pos);

	//return context;

	CloseHandle(g_hChildStd_IN_Wr);
	CloseHandle(g_hChildStd_OUT_Rd);

	if (retStr.find("Low Mandatory Level") != std::string::npos)
		return "Low Mandatory Level";

	if (retStr.find("Medium Mandatory Level") != std::string::npos)
		return "Medium Mandatory Level";

	if (retStr.find("High Mandatory Level") != std::string::npos)
		return "High Mandatory Level";

	Log("[!] Error extracting context", utilComponentName);
	return "";
}