#ifndef UNICODE
#define UNICODE
#endif 

#include <Windows.h>
#include <TlHelp32.h>
#include <filesystem>
#include <string>
#include "..\include\logger.hpp"
#include "..\include\header.hpp"
#include "..\include\util.hpp"

void Init();
int EnableDebugPrivs();
DWORD FindTarget(std::wstring targetProc);
int ProcessInjection(DWORD targetPID, std::wstring dllPath);
void GuardInj(DWORD pid);
void GuardRun();
VOID UpdateServiceStatus(DWORD currentState);
DWORD ServiceHandler(DWORD controlCode, DWORD eventType, LPVOID eventData, LPVOID context);
VOID ExecuteServiceCode();