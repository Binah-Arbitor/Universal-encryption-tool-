#include "bitoperation.hpp"
#include <cstddef>

void xor_cipher_repeating_key(std::vector<uint8_t>& data, const std::vector<uint8_t>& key_vector) {
    if (key_vector.empty()) {
        return; // No key provided, do nothing
    }
    
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key_vector[i % key_vector.size()];
    }
}

void rotl(std::vector<uint8_t>& data, int shift) {
    shift = shift % 8; // Only need to shift within byte boundary
    if (shift == 0) {
        return;
    }
    
    for (auto& byte : data) {
        byte = (byte << shift) | (byte >> (8 - shift));
    }
}

void rotr(std::vector<uint8_t>& data, int shift) {
    shift = shift % 8; // Only need to shift within byte boundary
    if (shift == 0) {
        return;
    }
    
    for (auto& byte : data) {
        byte = (byte >> shift) | (byte << (8 - shift));
    }
}