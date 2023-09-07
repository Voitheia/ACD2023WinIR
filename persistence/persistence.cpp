#include "persistence.hpp"

std::string componentName = "persistence";

int wmain() {
	Log("[+] Starting " + componentName + ".", componentName);
	Log("[*] Running as " + RunWhoami(), componentName);

	return 0;
}