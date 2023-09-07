#include "util.hpp"

std::string utilComponentName = "util";

std::string RunWhoami() {
	// https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output

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
		(LPWSTR)cmdline.c_str(),
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

	return retStr;
}