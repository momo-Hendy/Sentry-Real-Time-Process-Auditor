# ============================================================
# Sentry v1.0 — Cross-platform Makefile
# Targets:
#   make linux   — native Linux binary  (gcc + OpenSSL)
#   make windows — Windows .exe         (mingw-w64, no OpenSSL)
#   make test    — integration test     (linux build)
#   make clean   — remove build artefacts
# ============================================================

CC_LINUX   = gcc
CC_WINDOWS = x86_64-w64-mingw32-gcc

CFLAGS = -Wall -Wextra -g -I./shared -Wno-deprecated-declarations

SRC = \
    src/main.c \
    src/bridge/python_bridge.c \
    src/monitor/scanner.c \
    src/monitor/baseline.c \
    src/comparator/hasher.c

BIN_DIR = bin

# ── Default ──────────────────────────────────────────────────────────────
all: linux

# ── Linux build (gcc + OpenSSL) ──────────────────────────────────────────
linux: $(BIN_DIR)
	$(CC_LINUX) $(CFLAGS) $(SRC) -o $(BIN_DIR)/bridge \
	    -static -lssl -lcrypto -lpthread -ldl

# ── Windows cross-compile (mingw-w64, standalone SHA-256) ────────────────
windows: $(BIN_DIR)
	$(CC_WINDOWS) -O2 -I./shared $(SRC) -o $(BIN_DIR)/sentry_core.exe \
	    -lws2_32

# ── Output directory ─────────────────────────────────────────────────────
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# ── Integration test (two scan passes: baseline then tamper detection) ───
test: linux
	@echo "=== [1/5] Preparing directories ==="
	@mkdir -p /app/logs /app/test_files /var/lib/sentry /var/log

	@echo "=== [2/5] Creating test files ==="
	@echo "normal config value=42"  > /app/test_files/config.txt
	@echo "sensitive data"          > /app/test_files/secret.txt

	@echo "=== [3/5] First scan — establishes baseline ==="
	@timeout 3 ./$(BIN_DIR)/bridge || true

	@echo "=== [4/5] Tampering with a file ==="
	@echo "INJECTED"               > /app/test_files/secret.txt

	@echo "=== [5/5] Second scan — should detect the change ==="
	@timeout 3 ./$(BIN_DIR)/bridge || true

	@echo ""
	@echo "=== audit.json ==="
	@cat /app/logs/audit.json 2>/dev/null || echo "(no findings logged)"

# ── Clean ─────────────────────────────────────────────────────────────────
clean:
	rm -rf $(BIN_DIR)

.PHONY: all linux windows test clean
