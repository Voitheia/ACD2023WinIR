#include "decode.hpp"

int wmain() {
	std::string str;
	std::ifstream file(L"lab6logs.txt", std::ios::binary);
	if (file.is_open()) {
		while (getline(file, str)) {
			std::cout << logger::doXOR(base64_decode(str));
		}
	}
	file.close();
	int x;
	std::cin >> x;

	return 0;
}