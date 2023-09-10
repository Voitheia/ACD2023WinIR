#include <Windows.h>
#include <memory>
#include <string>
#include "logger.hpp"

std::string GetUserAndContext();
void CreateProc(std::string name, std::string cmdline);
std::string CreateProcRedirIO(std::string name, std::string cmdline);