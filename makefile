# ==============================
# SENTRY v1.0 - Makefile
# ==============================

CC = gcc

CFLAGS = -Wall -Wextra -g -I./shared -Wno-deprecated-declarations

LDFLAGS = -lssl -lcrypto

# Source Files
SRC = \
    src/bridge/python_bridge.c \
    src/monitor/scanner.c \
    src/monitor/baseline.c \
    src/comparator/hasher.c

# Output
BIN_DIR = bin
TARGET = $(BIN_DIR)/bridge

# Default target
all: $(TARGET)

# Create bin directory if it does not exist
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Build target
$(TARGET): $(SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean
