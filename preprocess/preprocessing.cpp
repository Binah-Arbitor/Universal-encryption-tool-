#include "preprocessing.hpp"

#include <stdio.h>
#include <iostream>
#include <vector>
#include <numeric>
#include <algorithm>

std::vector<uint8_t> data_to_bytes(const std::string& data) {
	const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(data.data());
	return std::vector<uint8_t>(data_ptr, data_ptr + data.size());
}

std::string bytes_to_data(const std::vector<uint8_t>& bytes) {
	return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}
