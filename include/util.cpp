#include "util.hpp"

std::string utilComponentName = "util";

std::string GetUserAndContext() {
	return CreateProcRedirIO("whoami", "cmd.exe /c whoami") +
		" " + CreateProcRedirIO("whoami /groups", "cmd.exe /c whoami /groups");
}

void CreateProc(std::string name, std::string cmdline) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(
		NULL,
		const_cast<LPSTR>(cmdline.c_str()),
		NULL,
		NULL,
		FALSE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi
	)) {
		Log("[!] Failed to create " + name + " process." + std::to_string(GetLastError()), utilComponentName);
	}
	else {
		Log("[+] " + name + " process spawned.", utilComponentName);
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

std::string CreateProcRedirIO(std::string name, std::string cmdline) {
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
		Log("[!] " + name + " StdoutRd CreatePipe: " + std::to_string(GetLastError()), utilComponentName);

	if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
		Log("[!] " + name + " Stdout SetHandleInformation: " + std::to_string(GetLastError()), utilComponentName);

	if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
		Log("[!] " + name + " Stdin CreatePipe: " + std::to_string(GetLastError()), utilComponentName);

	if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
		Log("[!] " + name + " Stdin SetHandleInformation: " + std::to_string(GetLastError()), utilComponentName);

	PROCESS_INFORMATION piProcInfo;
	STARTUPINFOA siStartInfo;
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

	bSuccess = CreateProcessA(
		NULL,
		const_cast<LPSTR>(cmdline.c_str()),
		NULL,
		NULL,
		TRUE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&siStartInfo,
		&piProcInfo
	);

	if (!bSuccess) {
		Log("[!] " + name + " CreateProcessW: " + std::to_string(GetLastError()), utilComponentName);
	}
	else {
		CloseHandle(piProcInfo.hProcess);
		CloseHandle(piProcInfo.hThread);
		CloseHandle(g_hChildStd_OUT_Wr);
		CloseHandle(g_hChildStd_IN_Rd);
		Log("[+] Successfully created " + name + " process.", utilComponentName);
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