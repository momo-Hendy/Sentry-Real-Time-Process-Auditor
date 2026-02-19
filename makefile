# Compiler and Flags
CC     = gcc
CFLAGS = -Wall -Wextra -g -I./shared -Wno-deprecated-declarations
LDFLAGS = -lssl -lcrypto

# Source files
SRC = \
    src/main.c \
    src/bridge/python_bridge.c \
    src/monitor/scanner.c \
    src/monitor/baseline.c \
    src/comparator/hasher.c

# Output
BIN_DIR = bin
TARGET  = $(BIN_DIR)/bridge

# Default rule
all: setup $(TARGET)

# Create output directory
setup:
	mkdir -p $(BIN_DIR)

# Build binary
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Run integration test (two scan passes: baseline, then tamper detection)
test: $(TARGET)
	@echo "=== [1/5] Preparing directories ==="
	@mkdir -p /app/logs /app/test_files /var/lib/sentry /var/log

	@echo "=== [2/5] Creating test files ==="
	@echo "normal config value=42"  > /app/test_files/config.txt
	@echo "sensitive data"          > /app/test_files/secret.txt

	@echo "=== [3/5] First scan — establishes baseline ==="
	@timeout 3 ./$(TARGET) || true

	@echo "=== [4/5] Tampering with a file ==="
	@echo "INJECTED"               > /app/test_files/secret.txt

	@echo "=== [5/5] Second scan — should detect the change ==="
	@timeout 3 ./$(TARGET) || true

	@echo ""
	@echo "=== audit.json ==="
	@cat /app/logs/audit.json 2>/dev/null || echo "(no findings logged)"

# Clean up build files
clean:
	rm -rf $(BIN_DIR)/*

.PHONY: all setup clean test
