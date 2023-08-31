// source: https://github.com/ReneNyffenegger/cpp-base64/blob/master/base64.h

#include <string_view>

std::string base64_encode(std::string_view s, bool url = false);
std::string base64_encode(unsigned char const* bytes_to_encode, size_t in_len, bool url);
std::string base64_decode(std::string_view s, bool remove_linebreaks = false);