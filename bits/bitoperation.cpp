#include "bitoperation.hpp"
#include <algorithm>

void xor_cipher_repeating_key(std::vector<uint8_t>& data, const std::vector<uint8_t>& key_vector) {
    if (key_vector.empty()) {
        return; // No key provided, no operation
    }
    
    size_t key_size = key_vector.size();
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key_vector[i % key_size];
    }
}

void rotl(std::vector<uint8_t>& data, int shift) {
    // Normalize shift to be within 0-7 range for 8-bit rotation
    shift = shift % 8;
    if (shift < 0) {
        shift += 8;
    }
    
    for (auto& byte : data) {
        byte = (byte << shift) | (byte >> (8 - shift));
    }
}

void rotr(std::vector<uint8_t>& data, int shift) {
    // Normalize shift to be within 0-7 range for 8-bit rotation
    shift = shift % 8;
    if (shift < 0) {
        shift += 8;
    }
    
    for (auto& byte : data) {
        byte = (byte >> shift) | (byte << (8 - shift));
    }
}
