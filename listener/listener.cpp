#include "listener.hpp"

std::string componentName = "listener";

int wmain() {
	Log("[+] Starting " + componentName + ".", componentName);
	Log("[*] Running as " + UserRunningProcess(), componentName);

	return 0;
}