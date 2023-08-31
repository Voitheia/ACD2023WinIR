#pragma once

#include <mutex>
#include <fstream>
#include <chrono>
#include <list>
#include "base64.hpp"

namespace logger {
	void Log(std::string msg);
	std::string PrependTime(std::string s);
	//std::list<char> doXOR(std::string s);
	std::string doXOR(std::string s);
}