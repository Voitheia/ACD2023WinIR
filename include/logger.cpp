#include "logger.hpp"

std::string logFileName = "lab6logs";
std::string logFileExt = ".txt";
std::string logFileDir = "C:\\Temp\\";
char key[11] = { 'A','r','m','o','r','e','d','C','o','r','e' };
bool logging = true;
bool encode = false;

void Log(std::string msg, std::string caller) {
	msg = caller + " " + msg;

	if (!logging) {
		std::cout << PrependTime(msg) << std::endl;
		return;
	}

	std::string logFilePath = logFileDir + logFileName + caller + logFileExt;
	std::string encStr = encode ? base64_encode(doXOR(PrependTime(msg)), false) : PrependTime(msg);

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