# ==============================
# SENTRY v1.0 - Makefile
# ==============================

CC = gcc

CFLAGS = -Wall -Wextra -g -I./shared -Wno-deprecated-declarations

LDFLAGS = -lssl -lcrypto

# Source Files
SRC = \
    src/main.c \
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
test: $(TARGET)
	@echo " Starting Integration Test..."
	@mkdir -p /app/logs
	@mkdir -p /var/lib/sentry
	@mkdir -p /var/log/sentry
	@./$(TARGET)
	@echo "\n Validating JSON Output in audit.json:"
	@cat /app/logs/audit.json
	@echo "\n Test Complete."
reset-logs:
	@mkdir -p logs
	@echo "Timestamp,Event_ID,File_Path,Severity,ISO_Reference,AI_Verdict,Action_Taken" > logs/monthly_audit.csv
	@rm -f logs/audit.json
	@echo " Logs reset for new audit cycle."
# Clean build artifacts
clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean
