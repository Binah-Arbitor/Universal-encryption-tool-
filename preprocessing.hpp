#pragma once

#include <vector>
#include <string>
#include <cstdint>

std::vector<uint8_t> data_to_bytes(const std::string& data);
std::string bytes_to_data(const std::vector<uint8_t>& bytes);

