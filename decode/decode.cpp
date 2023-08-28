#include "decode.hpp"

int wmain() {
	std::string str;
	std::ifstream file(L"lab6logs.txt", std::ios::binary);
	if (file.is_open()) {
		file >> str;
		std::cout << logger::doXOR(str) << std::endl;
	}

	int x;
	std::cin >> x;

	return 0;
}