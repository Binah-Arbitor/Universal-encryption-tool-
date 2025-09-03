#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <functional>

// Forward declarations
class CipherAlgorithm;
class ThreadPool;

// Progress callback function type
using ProgressCallback = std::function<void(double percentage, const std::string& message)>;

// Cipher modes enumeration
enum class CipherMode {
    ECB,    // Electronic Codebook
    CBC,    // Cipher Block Chaining
    CFB,    // Cipher Feedback
    OFB,    // Output Feedback
    CTR,    // Counter
    GCM     // Galois/Counter Mode
};

// Key sizes enumeration
enum class KeySize {
    KEY_128 = 16,
    KEY_192 = 24,
    KEY_256 = 32
};

// Cipher operation type
enum class CipherOperation {
    ENCRYPT,
    DECRYPT
};

// Base class for all cipher algorithms
class CipherAlgorithm {
public:
    virtual ~CipherAlgorithm() = default;
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, 
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv = {},
                                        ProgressCallback callback = nullptr) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, 
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv = {},
                                        ProgressCallback callback = nullptr) = 0;
    virtual std::string getName() const = 0;
    virtual bool supportsMultithreading() const = 0;
    virtual size_t getBlockSize() const = 0;
    virtual std::vector<KeySize> getSupportedKeySizes() const = 0;
    virtual std::vector<CipherMode> getSupportedModes() const = 0;
};

// Factory class for creating cipher algorithms
class CipherFactory {
public:
    static std::unique_ptr<CipherAlgorithm> createAES(CipherMode mode = CipherMode::CBC);
    static std::unique_ptr<CipherAlgorithm> createDES(CipherMode mode = CipherMode::CBC);
    static std::unique_ptr<CipherAlgorithm> create3DES(CipherMode mode = CipherMode::CBC);
    static std::unique_ptr<CipherAlgorithm> createChaCha20();
    static std::unique_ptr<CipherAlgorithm> createBlowfish(CipherMode mode = CipherMode::CBC);
    static std::unique_ptr<CipherAlgorithm> createTwofish(CipherMode mode = CipherMode::CBC);
    static std::unique_ptr<CipherAlgorithm> createRC4();
    
    static std::vector<std::string> getAvailableAlgorithms();
};

// Utility functions for encryption operations
namespace CryptoUtils {
    std::vector<uint8_t> generateRandomBytes(size_t length);
    std::vector<uint8_t> generateIV(size_t length);
    std::vector<uint8_t> deriveKey(const std::string& password, const std::vector<uint8_t>& salt, 
                                  size_t keyLength, size_t iterations = 10000);
    std::vector<uint8_t> padPKCS7(const std::vector<uint8_t>& data, size_t blockSize);
    std::vector<uint8_t> unpadPKCS7(const std::vector<uint8_t>& data);
    bool isValidPKCS7Padding(const std::vector<uint8_t>& data, size_t blockSize);
}