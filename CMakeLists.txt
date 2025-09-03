cmake_minimum_required(VERSION 3.12)
project(UniversalEncryptionTool VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add compile options
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/bits)
include_directories(${CMAKE_SOURCE_DIR}/preprocess)
include_directories(${CMAKE_SOURCE_DIR}/crypto)

# Find required packages
find_package(Threads REQUIRED)

# Source files
set(SOURCES
    bits/bitoperation.cpp
    preprocess/preprocessing.cpp
    crypto/cipher.cpp
    crypto/aes.cpp
    crypto/threadpool.cpp
)

# Create library
add_library(encryption_core STATIC ${SOURCES})
target_link_libraries(encryption_core Threads::Threads)

# Create main executable
add_executable(encryption_tool main.cpp)
target_link_libraries(encryption_tool encryption_core Threads::Threads)

# Enable testing
enable_testing()

# Add test executable if tests exist
if(EXISTS "${CMAKE_SOURCE_DIR}/tests")
    add_subdirectory(tests)
endif()