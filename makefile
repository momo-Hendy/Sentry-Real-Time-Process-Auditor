# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -g -I./shared

# Directories
SRC_DIR = src/bridge
BIN_DIR = bin

# Targets
TARGET = $(BIN_DIR)/bridge

# Default rule: Build the bridge
all: setup $(TARGET)

# Create the bin directory if it doesn't exist
setup:
	mkdir -p $(BIN_DIR)

# Compile the bridge
$(TARGET): $(SRC_DIR)/python_bridge.c
	$(CC) $(CFLAGS) $(SRC_DIR)/python_bridge.c -o $(TARGET)

# Clean up build files
clean:
	rm -rf $(BIN_DIR)/*