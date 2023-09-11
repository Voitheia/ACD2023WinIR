#ifndef UNICODE
#define UNICODE
#endif 

#include <winsock2.h>
#include <ws2tcpip.h>
#include <TlHelp32.h>
#include "..\include\logger.hpp"
#include "..\include\header.hpp"
#include "..\include\util.hpp"

#pragma comment(lib, "ws2_32.lib")

int Init();