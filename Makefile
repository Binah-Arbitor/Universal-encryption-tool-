# Universal Encryption Tool Makefile

CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11 -O2
INCLUDE_DIRS = -Ibits -Ipreprocess

# Source files
SOURCES = bits/bitoperation.cpp preprocess/preprocessing.cpp
OBJECTS = $(SOURCES:.cpp=.o)
LIBRARY = libencryption.a
TEST_EXECUTABLE = test

# Default target
all: $(LIBRARY)

# Create static library
$(LIBRARY): $(OBJECTS)
	ar rcs $@ $^
	@echo "Built library: $(LIBRARY)"

# Compile source files to object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE_DIRS) -c $< -o $@

# Build and run tests
run-tests: $(TEST_EXECUTABLE)
	./$(TEST_EXECUTABLE)

# Build test executable
$(TEST_EXECUTABLE): test.cpp $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDE_DIRS) $^ -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(LIBRARY) $(TEST_EXECUTABLE)
	@echo "Cleaned build artifacts"

# Install (optional, copies headers and library to system directories)
install: $(LIBRARY)
	@echo "Install target not implemented"

# Rebuild everything
rebuild: clean all

.PHONY: all clean install rebuild run-tests