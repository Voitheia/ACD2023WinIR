#include "persistence.hpp"

std::string componentName = "persistence";

int wmain() {
	Log("[+] Starting " + componentName + ".", componentName);
	Log("[*] Running as " + GetUserAndContext(), componentName);

	return 0;
}