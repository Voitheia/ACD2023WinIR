#pragma once

#include <mutex>
#include <fstream>
#include <chrono>

namespace logger {
	void Log(std::string msg);
	std::string PrependTime(std::string s);
	std::string doXOR(std::string s);
}