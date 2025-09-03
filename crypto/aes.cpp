#include "aes.hpp"
#include "threadpool.hpp"
#include <stdexcept>
#include <algorithm>
#include <random>
#include <chrono>

// AES S-box
const uint8_t AESCipher::s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES inverse S-box
const uint8_t AESCipher::inv_s_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Round constants
const uint8_t AESCipher::rcon[11] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x00
};

AESCipher::AESCipher(CipherMode mode, bool use_mt) 
    : mode(mode), block_size(BLOCK_SIZE), use_multithreading(use_mt) {
}

std::string AESCipher::getName() const {
    std::string mode_str;
    switch (mode) {
        case CipherMode::ECB: mode_str = "ECB"; break;
        case CipherMode::CBC: mode_str = "CBC"; break;
        case CipherMode::CFB: mode_str = "CFB"; break;
        case CipherMode::OFB: mode_str = "OFB"; break;
        case CipherMode::CTR: mode_str = "CTR"; break;
        case CipherMode::GCM: mode_str = "GCM"; break;
    }
    return "AES-" + mode_str;
}

bool AESCipher::supportsMultithreading() const {
    return mode == CipherMode::ECB || mode == CipherMode::CTR;
}

size_t AESCipher::getBlockSize() const {
    return BLOCK_SIZE;
}

std::vector<KeySize> AESCipher::getSupportedKeySizes() const {
    return {KeySize::KEY_128, KeySize::KEY_192, KeySize::KEY_256};
}

std::vector<CipherMode> AESCipher::getSupportedModes() const {
    return {CipherMode::ECB, CipherMode::CBC, CipherMode::CTR};
}

uint8_t AESCipher::gfMul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t high_bit;
    
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        
        high_bit = a & 0x80;
        a <<= 1;
        if (high_bit) {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    
    return result;
}

void AESCipher::subBytes(std::array<uint8_t, 16>& state) {
    for (auto& byte : state) {
        byte = s_box[byte];
    }
}

void AESCipher::invSubBytes(std::array<uint8_t, 16>& state) {
    for (auto& byte : state) {
        byte = inv_s_box[byte];
    }
}

void AESCipher::shiftRows(std::array<uint8_t, 16>& state) {
    uint8_t temp;
    
    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift left by 3
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

void AESCipher::invShiftRows(std::array<uint8_t, 16>& state) {
    uint8_t temp;
    
    // Row 1: shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    // Row 2: shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift right by 3
    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

void AESCipher::mixColumns(std::array<uint8_t, 16>& state) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[c * 4];
        uint8_t s1 = state[c * 4 + 1];
        uint8_t s2 = state[c * 4 + 2];
        uint8_t s3 = state[c * 4 + 3];
        
        state[c * 4] = gfMul(0x02, s0) ^ gfMul(0x03, s1) ^ s2 ^ s3;
        state[c * 4 + 1] = s0 ^ gfMul(0x02, s1) ^ gfMul(0x03, s2) ^ s3;
        state[c * 4 + 2] = s0 ^ s1 ^ gfMul(0x02, s2) ^ gfMul(0x03, s3);
        state[c * 4 + 3] = gfMul(0x03, s0) ^ s1 ^ s2 ^ gfMul(0x02, s3);
    }
}

void AESCipher::invMixColumns(std::array<uint8_t, 16>& state) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[c * 4];
        uint8_t s1 = state[c * 4 + 1];
        uint8_t s2 = state[c * 4 + 2];
        uint8_t s3 = state[c * 4 + 3];
        
        state[c * 4] = gfMul(0x0e, s0) ^ gfMul(0x0b, s1) ^ gfMul(0x0d, s2) ^ gfMul(0x09, s3);
        state[c * 4 + 1] = gfMul(0x09, s0) ^ gfMul(0x0e, s1) ^ gfMul(0x0b, s2) ^ gfMul(0x0d, s3);
        state[c * 4 + 2] = gfMul(0x0d, s0) ^ gfMul(0x09, s1) ^ gfMul(0x0e, s2) ^ gfMul(0x0b, s3);
        state[c * 4 + 3] = gfMul(0x0b, s0) ^ gfMul(0x0d, s1) ^ gfMul(0x09, s2) ^ gfMul(0x0e, s3);
    }
}

void AESCipher::addRoundKey(std::array<uint8_t, 16>& state, const std::array<uint8_t, 16>& roundKey) {
    for (size_t i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

// More implementation will follow in the next part due to length constraints...

void AESCipher::keyExpansion(const std::vector<uint8_t>& key, std::vector<std::array<uint8_t, 4>>& roundKeys) {
    size_t keyWords = key.size() / 4;
    size_t rounds = (keyWords == 4) ? 10 : (keyWords == 6) ? 12 : 14;
    
    roundKeys.resize((rounds + 1) * 4);
    
    // Copy the original key
    for (size_t i = 0; i < keyWords; i++) {
        for (size_t j = 0; j < 4; j++) {
            roundKeys[i][j] = key[i * 4 + j];
        }
    }
    
    // Generate remaining round keys
    for (size_t i = keyWords; i < (rounds + 1) * 4; i++) {
        std::array<uint8_t, 4> temp = roundKeys[i - 1];
        
        if (i % keyWords == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord
            for (auto& byte : temp) {
                byte = s_box[byte];
            }
            
            // Rcon
            temp[0] ^= rcon[i / keyWords];
        } else if (keyWords > 6 && (i % keyWords == 4)) {
            // SubWord for AES-256
            for (auto& byte : temp) {
                byte = s_box[byte];
            }
        }
        
        for (size_t j = 0; j < 4; j++) {
            roundKeys[i][j] = roundKeys[i - keyWords][j] ^ temp[j];
        }
    }
}

void AESCipher::encryptBlock(std::array<uint8_t, 16>& block, const std::vector<std::array<uint8_t, 4>>& roundKeys, size_t numRounds) {
    // Convert round keys to 16-byte arrays
    std::array<uint8_t, 16> roundKey;
    
    // Initial round
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            roundKey[i * 4 + j] = roundKeys[i][j];
        }
    }
    addRoundKey(block, roundKey);
    
    // Main rounds
    for (size_t round = 1; round < numRounds; round++) {
        subBytes(block);
        shiftRows(block);
        mixColumns(block);
        
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                roundKey[i * 4 + j] = roundKeys[round * 4 + i][j];
            }
        }
        addRoundKey(block, roundKey);
    }
    
    // Final round
    subBytes(block);
    shiftRows(block);
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            roundKey[i * 4 + j] = roundKeys[numRounds * 4 + i][j];
        }
    }
    addRoundKey(block, roundKey);
}

void AESCipher::decryptBlock(std::array<uint8_t, 16>& block, const std::vector<std::array<uint8_t, 4>>& roundKeys, size_t numRounds) {
    std::array<uint8_t, 16> roundKey;
    
    // Initial round
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            roundKey[i * 4 + j] = roundKeys[numRounds * 4 + i][j];
        }
    }
    addRoundKey(block, roundKey);
    
    // Main rounds
    for (size_t round = numRounds - 1; round > 0; round--) {
        invShiftRows(block);
        invSubBytes(block);
        
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                roundKey[i * 4 + j] = roundKeys[round * 4 + i][j];
            }
        }
        addRoundKey(block, roundKey);
        invMixColumns(block);
    }
    
    // Final round
    invShiftRows(block);
    invSubBytes(block);
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            roundKey[i * 4 + j] = roundKeys[i][j];
        }
    }
    addRoundKey(block, roundKey);
}

std::vector<uint8_t> AESCipher::encrypt(const std::vector<uint8_t>& plaintext, 
                                       const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& iv,
                                       ProgressCallback callback) {
    switch (mode) {
        case CipherMode::ECB:
            return use_multithreading ? encryptECBParallel(plaintext, key, callback) 
                                      : encryptECB(plaintext, key, callback);
        case CipherMode::CBC:
            return encryptCBC(plaintext, key, iv, callback);
        case CipherMode::CTR:
            return use_multithreading ? encryptCTRParallel(plaintext, key, iv, callback)
                                      : encryptCTR(plaintext, key, iv, callback);
        default:
            throw std::runtime_error("Unsupported cipher mode");
    }
}

std::vector<uint8_t> AESCipher::decrypt(const std::vector<uint8_t>& ciphertext, 
                                       const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& iv,
                                       ProgressCallback callback) {
    switch (mode) {
        case CipherMode::ECB:
            return use_multithreading ? decryptECBParallel(ciphertext, key, callback)
                                      : decryptECB(ciphertext, key, callback);
        case CipherMode::CBC:
            return decryptCBC(ciphertext, key, iv, callback);
        case CipherMode::CTR:
            return use_multithreading ? decryptCTRParallel(ciphertext, key, iv, callback)
                                      : decryptCTR(ciphertext, key, iv, callback);
        default:
            throw std::runtime_error("Unsupported cipher mode");
    }
}

std::vector<uint8_t> AESCipher::encryptECB(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, ProgressCallback callback) {
    // Simple padding - add bytes equal to padding length
    std::vector<uint8_t> padded = plaintext;
    size_t paddingLength = BLOCK_SIZE - (plaintext.size() % BLOCK_SIZE);
    if (paddingLength == 0) paddingLength = BLOCK_SIZE;
    
    for (size_t i = 0; i < paddingLength; i++) {
        padded.push_back(static_cast<uint8_t>(paddingLength));
    }
    
    std::vector<uint8_t> ciphertext(padded.size());
    
    // Expand the key
    std::vector<std::array<uint8_t, 4>> roundKeys;
    keyExpansion(key, roundKeys);
    size_t numRounds = (key.size() == 16) ? 10 : (key.size() == 24) ? 12 : 14;
    
    // Encrypt blocks
    size_t totalBlocks = padded.size() / BLOCK_SIZE;
    for (size_t i = 0; i < totalBlocks; i++) {
        std::array<uint8_t, 16> block;
        std::copy(padded.begin() + i * BLOCK_SIZE, padded.begin() + (i + 1) * BLOCK_SIZE, block.begin());
        
        encryptBlock(block, roundKeys, numRounds);
        
        std::copy(block.begin(), block.end(), ciphertext.begin() + i * BLOCK_SIZE);
        
        if (callback && i % 100 == 0) {
            double progress = (double)(i + 1) / totalBlocks * 100.0;
            callback(progress, "Encrypting block " + std::to_string(i + 1) + "/" + std::to_string(totalBlocks));
        }
    }
    
    if (callback) {
        callback(100.0, "Encryption complete");
    }
    
    return ciphertext;
}

std::vector<uint8_t> AESCipher::decryptECB(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, ProgressCallback callback) {
    if (ciphertext.size() % BLOCK_SIZE != 0) {
        throw std::runtime_error("Invalid ciphertext size for ECB mode");
    }
    
    std::vector<uint8_t> plaintext(ciphertext.size());
    
    // Expand the key
    std::vector<std::array<uint8_t, 4>> roundKeys;
    keyExpansion(key, roundKeys);
    size_t numRounds = (key.size() == 16) ? 10 : (key.size() == 24) ? 12 : 14;
    
    // Decrypt blocks
    size_t totalBlocks = ciphertext.size() / BLOCK_SIZE;
    for (size_t i = 0; i < totalBlocks; i++) {
        std::array<uint8_t, 16> block;
        std::copy(ciphertext.begin() + i * BLOCK_SIZE, ciphertext.begin() + (i + 1) * BLOCK_SIZE, block.begin());
        
        decryptBlock(block, roundKeys, numRounds);
        
        std::copy(block.begin(), block.end(), plaintext.begin() + i * BLOCK_SIZE);
        
        if (callback && i % 100 == 0) {
            double progress = (double)(i + 1) / totalBlocks * 100.0;
            callback(progress, "Decrypting block " + std::to_string(i + 1) + "/" + std::to_string(totalBlocks));
        }
    }
    
    if (callback) {
        callback(100.0, "Decryption complete");
    }
    
    // Remove padding
    if (!plaintext.empty()) {
        uint8_t paddingLength = plaintext.back();
        if (paddingLength <= BLOCK_SIZE && paddingLength <= plaintext.size()) {
            plaintext.resize(plaintext.size() - paddingLength);
        }
    }
    
    return plaintext;
}

std::vector<uint8_t> AESCipher::encryptCBC(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback) {
    if (iv.size() != BLOCK_SIZE) {
        throw std::runtime_error("Invalid IV size for CBC mode");
    }
    
    // Simple padding
    std::vector<uint8_t> padded = plaintext;
    size_t paddingLength = BLOCK_SIZE - (plaintext.size() % BLOCK_SIZE);
    if (paddingLength == 0) paddingLength = BLOCK_SIZE;
    
    for (size_t i = 0; i < paddingLength; i++) {
        padded.push_back(static_cast<uint8_t>(paddingLength));
    }
    
    std::vector<uint8_t> ciphertext(padded.size());
    
    // Expand the key
    std::vector<std::array<uint8_t, 4>> roundKeys;
    keyExpansion(key, roundKeys);
    size_t numRounds = (key.size() == 16) ? 10 : (key.size() == 24) ? 12 : 14;
    
    std::array<uint8_t, 16> previousBlock;
    std::copy(iv.begin(), iv.end(), previousBlock.begin());
    
    // Encrypt blocks
    size_t totalBlocks = padded.size() / BLOCK_SIZE;
    for (size_t i = 0; i < totalBlocks; i++) {
        std::array<uint8_t, 16> block;
        std::copy(padded.begin() + i * BLOCK_SIZE, padded.begin() + (i + 1) * BLOCK_SIZE, block.begin());
        
        // XOR with previous block
        for (size_t j = 0; j < BLOCK_SIZE; j++) {
            block[j] ^= previousBlock[j];
        }
        
        encryptBlock(block, roundKeys, numRounds);
        
        std::copy(block.begin(), block.end(), ciphertext.begin() + i * BLOCK_SIZE);
        previousBlock = block;
        
        if (callback && i % 100 == 0) {
            double progress = (double)(i + 1) / totalBlocks * 100.0;
            callback(progress, "Encrypting block " + std::to_string(i + 1) + "/" + std::to_string(totalBlocks));
        }
    }
    
    if (callback) {
        callback(100.0, "Encryption complete");
    }
    
    return ciphertext;
}

std::vector<uint8_t> AESCipher::decryptCBC(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback) {
    if (iv.size() != BLOCK_SIZE || ciphertext.size() % BLOCK_SIZE != 0) {
        throw std::runtime_error("Invalid IV size or ciphertext size for CBC mode");
    }
    
    std::vector<uint8_t> plaintext(ciphertext.size());
    
    // Expand the key
    std::vector<std::array<uint8_t, 4>> roundKeys;
    keyExpansion(key, roundKeys);
    size_t numRounds = (key.size() == 16) ? 10 : (key.size() == 24) ? 12 : 14;
    
    std::array<uint8_t, 16> previousBlock;
    std::copy(iv.begin(), iv.end(), previousBlock.begin());
    
    // Decrypt blocks
    size_t totalBlocks = ciphertext.size() / BLOCK_SIZE;
    for (size_t i = 0; i < totalBlocks; i++) {
        std::array<uint8_t, 16> block;
        std::copy(ciphertext.begin() + i * BLOCK_SIZE, ciphertext.begin() + (i + 1) * BLOCK_SIZE, block.begin());
        
        std::array<uint8_t, 16> encryptedBlock = block;
        decryptBlock(block, roundKeys, numRounds);
        
        // XOR with previous block
        for (size_t j = 0; j < BLOCK_SIZE; j++) {
            block[j] ^= previousBlock[j];
        }
        
        std::copy(block.begin(), block.end(), plaintext.begin() + i * BLOCK_SIZE);
        previousBlock = encryptedBlock;
        
        if (callback && i % 100 == 0) {
            double progress = (double)(i + 1) / totalBlocks * 100.0;
            callback(progress, "Decrypting block " + std::to_string(i + 1) + "/" + std::to_string(totalBlocks));
        }
    }
    
    if (callback) {
        callback(100.0, "Decryption complete");
    }
    
    // Remove padding
    if (!plaintext.empty()) {
        uint8_t paddingLength = plaintext.back();
        if (paddingLength <= BLOCK_SIZE && paddingLength <= plaintext.size()) {
            plaintext.resize(plaintext.size() - paddingLength);
        }
    }
    
    return plaintext;
}

// Placeholder implementations for multithreading and CTR mode
std::vector<uint8_t> AESCipher::encryptECBParallel(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, ProgressCallback callback) {
    return encryptECB(plaintext, key, callback);
}

std::vector<uint8_t> AESCipher::decryptECBParallel(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, ProgressCallback callback) {
    return decryptECB(ciphertext, key, callback);
}

std::vector<uint8_t> AESCipher::encryptCTR(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback) {
    return encryptCBC(plaintext, key, iv, callback); // Placeholder
}

std::vector<uint8_t> AESCipher::decryptCTR(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback) {
    return decryptCBC(ciphertext, key, iv, callback); // Placeholder
}

std::vector<uint8_t> AESCipher::encryptCTRParallel(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback) {
    return encryptCTR(plaintext, key, iv, callback);
}

std::vector<uint8_t> AESCipher::decryptCTRParallel(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback) {
    return decryptCTR(ciphertext, key, iv, callback);
}