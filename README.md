# Universal-encryption-tool-
General purpose encryption module (made with a clang) that can be extended with various algorithms 

## Build Instructions

This project uses a Makefile for building. To build the encryption library:

```bash
# Build the library
make

# Clean build artifacts
make clean

# Rebuild everything
make rebuild
```

## GitHub Actions

This project includes automated building through GitHub Actions. The workflow:
- Builds the project on every push and pull request
- Tests with both g++ and clang++ compilers
- Creates build artifacts for download

## Library Usage

The library provides two main modules:
- **bits**: XOR cipher and bit rotation operations
- **preprocess**: Data conversion between strings and byte vectors
