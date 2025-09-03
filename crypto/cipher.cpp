#include "cipher.hpp"
#include <random>
#include <chrono>
#include <algorithm>

#include "cipher.hpp"
#include "aes.hpp"
#include <random>
#include <chrono>
#include <algorithm>
#include <stdexcept>

// CipherFactory implementations
std::unique_ptr<CipherAlgorithm> CipherFactory::createAES(CipherMode mode) {
    return std::make_unique<AESCipher>(mode);
}

std::unique_ptr<CipherAlgorithm> CipherFactory::createDES(CipherMode mode) {
    throw std::runtime_error("DES not yet implemented");
}

std::unique_ptr<CipherAlgorithm> CipherFactory::create3DES(CipherMode mode) {
    throw std::runtime_error("3DES not yet implemented");
}

std::unique_ptr<CipherAlgorithm> CipherFactory::createChaCha20() {
    throw std::runtime_error("ChaCha20 not yet implemented");
}

std::unique_ptr<CipherAlgorithm> CipherFactory::createBlowfish(CipherMode mode) {
    throw std::runtime_error("Blowfish not yet implemented");
}

std::unique_ptr<CipherAlgorithm> CipherFactory::createTwofish(CipherMode mode) {
    throw std::runtime_error("Twofish not yet implemented");
}

std::unique_ptr<CipherAlgorithm> CipherFactory::createRC4() {
    throw std::runtime_error("RC4 not yet implemented");
}

std::vector<std::string> CipherFactory::getAvailableAlgorithms() {
    return {"AES-ECB", "AES-CBC", "AES-CTR"};
}

namespace CryptoUtils {
    std::vector<uint8_t> generateRandomBytes(size_t length) {
        std::vector<uint8_t> result(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        for (auto& byte : result) {
            byte = dis(gen);
        }
        
        return result;
    }

    std::vector<uint8_t> generateIV(size_t length) {
        return generateRandomBytes(length);
    }

    std::vector<uint8_t> deriveKey(const std::string& password, const std::vector<uint8_t>& salt, 
                                  size_t keyLength, size_t iterations) {
        // Simple PBKDF2-like key derivation (simplified for demo)
        std::vector<uint8_t> key(keyLength);
        std::vector<uint8_t> input = salt;
        
        // Append password to salt
        for (char c : password) {
            input.push_back(static_cast<uint8_t>(c));
        }
        
        // Simple iterative hashing
        for (size_t i = 0; i < iterations; i++) {
            // Simple hash function (not cryptographically secure, for demo only)
            for (size_t j = 0; j < input.size(); j++) {
                input[j] = (input[j] + 1) ^ (input[(j + 1) % input.size()]);
            }
        }
        
        // Fill key with derived data
        for (size_t i = 0; i < keyLength; i++) {
            key[i] = input[i % input.size()];
        }
        
        return key;
    }

    std::vector<uint8_t> padPKCS7(const std::vector<uint8_t>& data, size_t blockSize) {
        size_t paddingLength = blockSize - (data.size() % blockSize);
        if (paddingLength == 0) {
            paddingLength = blockSize;
        }
        
        std::vector<uint8_t> padded = data;
        for (size_t i = 0; i < paddingLength; i++) {
            padded.push_back(static_cast<uint8_t>(paddingLength));
        }
        
        return padded;
    }

    std::vector<uint8_t> unpadPKCS7(const std::vector<uint8_t>& data) {
        if (data.empty()) {
            return data;
        }
        
        uint8_t paddingLength = data.back();
        if (paddingLength == 0 || paddingLength > data.size()) {
            throw std::runtime_error("Invalid PKCS7 padding");
        }
        
        // Verify padding
        for (size_t i = data.size() - paddingLength; i < data.size(); i++) {
            if (data[i] != paddingLength) {
                throw std::runtime_error("Invalid PKCS7 padding");
            }
        }
        
        return std::vector<uint8_t>(data.begin(), data.end() - paddingLength);
    }

    bool isValidPKCS7Padding(const std::vector<uint8_t>& data, size_t blockSize) {
        if (data.empty() || data.size() % blockSize != 0) {
            return false;
        }
        
        uint8_t paddingLength = data.back();
        if (paddingLength == 0 || paddingLength > blockSize) {
            return false;
        }
        
        for (size_t i = data.size() - paddingLength; i < data.size(); i++) {
            if (data[i] != paddingLength) {
                return false;
            }
        }
        
        return true;
    }
}