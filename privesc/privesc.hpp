#ifndef UNICODE
#define UNICODE
#endif 

#include <Windows.h>
#include <vector>
#include <string>
#include <memory>
#include <iostream>
#include <TlHelp32.h>
#include "..\include\logger.hpp"
#include "..\include\header.hpp"
#include "..\include\util.hpp"
#include "..\loader\embed.hpp"

int ImpersonateToken(DWORD dwPID, HANDLE* hNewToken);
int SystemToken(HANDLE* hNewToken);