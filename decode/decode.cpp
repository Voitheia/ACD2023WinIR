#include "decode.hpp"

int wmain() {
	std::string str;
	std::ifstream file(L"lab6logs.txt", std::ios::binary);
	if (file.is_open()) {
		while (getline(file, str)) {
			std::string out = logger::doXOR(str); // testing only
			std::cout << out << std::endl;
		}
	}
	file.close();
	int x;
	std::cin >> x;

	return 0;
}