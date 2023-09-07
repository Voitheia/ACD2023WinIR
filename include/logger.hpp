#pragma once

#include <mutex>
#include <fstream>
#include <chrono>
#include <list>
#include <iostream>
#include "base64.hpp"

void Log(std::string msg, std::string caller);
std::string PrependTime(std::string s);
std::string doXOR(std::string s);