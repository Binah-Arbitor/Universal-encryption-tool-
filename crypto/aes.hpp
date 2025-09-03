#pragma once

#include "cipher.hpp"
#include <array>

class AESCipher : public CipherAlgorithm {
private:
    CipherMode mode;
    size_t block_size;
    bool use_multithreading;
    
    // AES constants
    static constexpr size_t BLOCK_SIZE = 16;
    static constexpr size_t MAX_ROUNDS = 14;
    
    // AES S-box
    static const uint8_t s_box[256];
    static const uint8_t inv_s_box[256];
    
    // Round constants
    static const uint8_t rcon[11];
    
    // Key expansion
    std::vector<uint8_t> expandKey(const std::vector<uint8_t>& key);
    void keyExpansion(const std::vector<uint8_t>& key, std::vector<std::array<uint8_t, 4>>& roundKeys);
    
    // Core AES operations
    void subBytes(std::array<uint8_t, 16>& state);
    void invSubBytes(std::array<uint8_t, 16>& state);
    void shiftRows(std::array<uint8_t, 16>& state);
    void invShiftRows(std::array<uint8_t, 16>& state);
    void mixColumns(std::array<uint8_t, 16>& state);
    void invMixColumns(std::array<uint8_t, 16>& state);
    void addRoundKey(std::array<uint8_t, 16>& state, const std::array<uint8_t, 16>& roundKey);
    
    // Galois field multiplication
    uint8_t gfMul(uint8_t a, uint8_t b);
    
    // Block encryption/decryption
    void encryptBlock(std::array<uint8_t, 16>& block, const std::vector<std::array<uint8_t, 4>>& roundKeys, size_t numRounds);
    void decryptBlock(std::array<uint8_t, 16>& block, const std::vector<std::array<uint8_t, 4>>& roundKeys, size_t numRounds);
    
    // Mode-specific operations
    std::vector<uint8_t> encryptECB(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, ProgressCallback callback);
    std::vector<uint8_t> decryptECB(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, ProgressCallback callback);
    std::vector<uint8_t> encryptCBC(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback);
    std::vector<uint8_t> decryptCBC(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback);
    std::vector<uint8_t> encryptCTR(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback);
    std::vector<uint8_t> decryptCTR(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback);
    
    // Multithreading support
    std::vector<uint8_t> encryptECBParallel(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, ProgressCallback callback);
    std::vector<uint8_t> decryptECBParallel(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, ProgressCallback callback);
    std::vector<uint8_t> encryptCTRParallel(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback);
    std::vector<uint8_t> decryptCTRParallel(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, ProgressCallback callback);
    
public:
    explicit AESCipher(CipherMode mode = CipherMode::CBC, bool use_mt = true);
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, 
                                const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& iv = {},
                                ProgressCallback callback = nullptr) override;
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, 
                                const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& iv = {},
                                ProgressCallback callback = nullptr) override;
    
    std::string getName() const override;
    bool supportsMultithreading() const override;
    size_t getBlockSize() const override;
    std::vector<KeySize> getSupportedKeySizes() const override;
    std::vector<CipherMode> getSupportedModes() const override;
    
    void setMultithreading(bool enable) { use_multithreading = enable; }
};