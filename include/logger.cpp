#include "logger.hpp"

namespace logger {

std::wstring logFileName = L"lab6logs.txt";
std::wstring logFilePath = L"C:\\Temp\\" + logFileName;
std::mutex logMutex;
char key[11] = { 'A','r','m','o','r','e','d','C','o','r','e' };

void Log(std::string msg) {
	msg += "\n";
	std::string encStr = base64_encode(doXOR(PrependTime(msg)), false);

	std::lock_guard<std::mutex> guard(logMutex);
	std::ofstream log(logFilePath, std::ios::app | std::ios::binary);
	if (log.is_open()) {
		log << encStr << std::endl;
	}
	log.close();
}

std::string PrependTime(std::string s) {
	std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	std::string ts = std::ctime(&t);
	ts.resize(ts.size() - 1);
	return ts + " | " + s;
}

std::string doXOR(std::string s) {
	std::string out;

	int i = 0;
	for (char c : s) {
		out += c ^ key[i % (sizeof(key) / sizeof(char))];
		i++;
	}

	return out;
}

}