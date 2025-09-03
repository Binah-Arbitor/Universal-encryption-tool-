#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <thread>
#include <chrono>
#include <iomanip>
#include <functional>

#include "bitoperation.hpp"
#include "preprocessing.hpp"

// Progress callback function type
using ProgressCallback = std::function<void(double percentage, const std::string& message)>;

class EncryptionTool {
private:
    bool verbose;
    size_t thread_count;

public:
    EncryptionTool() : verbose(false), thread_count(std::thread::hardware_concurrency()) {}
    
    void setVerbose(bool v) { verbose = v; }
    bool getVerbose() const { return verbose; }
    void setThreadCount(size_t count) { thread_count = count; }
    
    void showProgress(double percentage, const std::string& message) {
        if (verbose) {
            std::cout << "\r[" << std::setw(6) << std::fixed << std::setprecision(2) 
                      << percentage << "%] " << message << std::flush;
            if (percentage >= 100.0) {
                std::cout << std::endl;
            }
        }
    }
    
    void testBasicOperations() {
        std::cout << "=== Testing Basic Bit Operations ===" << std::endl;
        
        // Test XOR cipher
        std::string plaintext = "Hello, World!";
        std::string key = "secret";
        
        auto data = data_to_bytes(plaintext);
        auto key_bytes = data_to_bytes(key);
        
        std::cout << "Original: " << plaintext << std::endl;
        
        // Encrypt
        xor_cipher_repeating_key(data, key_bytes);
        std::cout << "Encrypted (hex): ";
        for (auto byte : data) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        std::cout << std::dec << std::endl;
        
        // Decrypt (XOR is symmetric)
        xor_cipher_repeating_key(data, key_bytes);
        std::cout << "Decrypted: " << bytes_to_data(data) << std::endl;
        
        // Test rotation
        data = data_to_bytes("ABCD");
        std::cout << "\nTesting rotation on 'ABCD':" << std::endl;
        std::cout << "Original (hex): ";
        for (auto byte : data) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
        }
        std::cout << std::dec << std::endl;
        
        rotl(data, 2);
        std::cout << "After ROTL 2: ";
        for (auto byte : data) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
        }
        std::cout << std::dec << std::endl;
        
        rotr(data, 2);
        std::cout << "After ROTR 2: ";
        for (auto byte : data) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
        }
        std::cout << std::dec << std::endl;
        
        std::cout << "Back to: " << bytes_to_data(data) << std::endl;
    }
    
    void showMenu() {
        std::cout << "\n=== Universal Encryption Tool ===" << std::endl;
        std::cout << "1. Test Basic Operations" << std::endl;
        std::cout << "2. XOR Cipher with Repeating Key" << std::endl;
        std::cout << "3. File Encryption (Coming Soon)" << std::endl;
        std::cout << "4. AES Encryption (Coming Soon)" << std::endl;
        std::cout << "5. Settings" << std::endl;
        std::cout << "6. Exit" << std::endl;
        std::cout << "Choose an option: ";
    }
    
    void showSettings() {
        std::cout << "\n=== Settings ===" << std::endl;
        std::cout << "Current thread count: " << thread_count << std::endl;
        std::cout << "Verbose mode: " << (verbose ? "ON" : "OFF") << std::endl;
        std::cout << "\n1. Change thread count" << std::endl;
        std::cout << "2. Toggle verbose mode" << std::endl;
        std::cout << "3. Back to main menu" << std::endl;
        std::cout << "Choose an option: ";
    }
};

int main() {
    EncryptionTool tool;
    int choice;
    
    std::cout << "Universal Encryption Tool - Enhanced Version" << std::endl;
    std::cout << "Supporting multithreading and multiple symmetric ciphers" << std::endl;
    
    while (true) {
        tool.showMenu();
        std::cin >> choice;
        
        switch (choice) {
            case 1:
                tool.testBasicOperations();
                break;
                
            case 2: {
                std::cout << "Enter text to encrypt: ";
                std::cin.ignore();
                std::string text;
                std::getline(std::cin, text);
                
                std::cout << "Enter key: ";
                std::string key;
                std::getline(std::cin, key);
                
                auto data = data_to_bytes(text);
                auto key_bytes = data_to_bytes(key);
                
                tool.showProgress(0, "Starting XOR encryption...");
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                
                tool.showProgress(50, "Processing data...");
                xor_cipher_repeating_key(data, key_bytes);
                
                tool.showProgress(100, "Encryption complete!");
                
                std::cout << "Encrypted (hex): ";
                for (auto byte : data) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
                }
                std::cout << std::dec << std::endl;
                break;
            }
            
            case 3:
                std::cout << "File encryption will be implemented with AES and other algorithms." << std::endl;
                break;
                
            case 4:
                std::cout << "AES encryption will be implemented with multithreading support." << std::endl;
                break;
                
            case 5: {
                int settings_choice;
                tool.showSettings();
                std::cin >> settings_choice;
                
                switch (settings_choice) {
                    case 1: {
                        std::cout << "Enter new thread count (1-" << std::thread::hardware_concurrency() << "): ";
                        size_t new_count;
                        std::cin >> new_count;
                        if (new_count >= 1 && new_count <= std::thread::hardware_concurrency()) {
                            tool.setThreadCount(new_count);
                            std::cout << "Thread count updated to " << new_count << std::endl;
                        } else {
                            std::cout << "Invalid thread count!" << std::endl;
                        }
                        break;
                    }
                    case 2: {
                        bool current_verbose = tool.getVerbose(); // Get current state
                        tool.setVerbose(!current_verbose);
                        std::cout << "Verbose mode " << (!current_verbose ? "enabled" : "disabled") << std::endl;
                        break;
                    }
                    case 3:
                        break;
                    default:
                        std::cout << "Invalid option!" << std::endl;
                }
                break;
            }
            
            case 6:
                std::cout << "Thank you for using Universal Encryption Tool!" << std::endl;
                return 0;
                
            default:
                std::cout << "Invalid option! Please try again." << std::endl;
        }
    }
    
    return 0;
}