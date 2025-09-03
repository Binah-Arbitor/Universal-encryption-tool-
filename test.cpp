#include <iostream>
#include <vector>
#include <cassert>
#include "bitoperation.hpp"
#include "preprocessing.hpp"

int main() {
    std::cout << "Testing Universal Encryption Tool functions..." << std::endl;
    
    // Test preprocessing functions
    std::string test_string = "Hello, World!";
    std::vector<uint8_t> bytes = data_to_bytes(test_string);
    std::string recovered = bytes_to_data(bytes);
    assert(test_string == recovered);
    std::cout << "✓ Preprocessing functions work correctly" << std::endl;
    
    // Test XOR cipher
    std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    std::vector<uint8_t> key = {0x01, 0x02, 0x03};
    std::vector<uint8_t> original_data = data;
    
    xor_cipher_repeating_key(data, key);
    xor_cipher_repeating_key(data, key); // XOR twice should restore original
    assert(data == original_data);
    std::cout << "✓ XOR cipher functions work correctly" << std::endl;
    
    // Test bit rotation
    std::vector<uint8_t> rot_data = {0b11010010}; // 210 in binary
    std::vector<uint8_t> original_rot = rot_data;
    
    rotl(rot_data, 2);
    rotr(rot_data, 2); // Should restore original
    assert(rot_data == original_rot);
    std::cout << "✓ Bit rotation functions work correctly" << std::endl;
    
    std::cout << "All tests passed!" << std::endl;
    return 0;
}