#!/bin/bash
set -e

# Configuration
BUILD_DIR="bin"
LINUX_BINARY="${BUILD_DIR}/gdpr-scan-linux-amd64"
WINDOWS_BINARY="${BUILD_DIR}/gdpr-scan-windows-amd64.exe"

# 1. Clean previous builds
echo "==> Cleaning previous builds..."
make clean

# 2. Build for all platforms
echo "==> Building binaries (Linux, Windows)..."
make build-all

# 3. Verify Linux binary existence
if [ ! -f "$LINUX_BINARY" ]; then
  echo "[ERROR] Linux binary not found at $LINUX_BINARY"
  exit 1
fi
echo "[OK] Linux binary found."

# 4. Verify Windows binary existence
if [ ! -f "$WINDOWS_BINARY" ]; then
  echo "[ERROR] Windows binary not found at $WINDOWS_BINARY"
  exit 1
fi
echo "[OK] Windows binary found."

# 5. Smoke Test: Run Linux binary with --help
echo "==> Running smoke test (Linux binary --help)..."
if "$LINUX_BINARY" --help > /dev/null 2>&1; then
  echo "[OK] Binary executed successfully (help command works)."
else
  echo "[ERROR] Binary failed to execute or return success code."
  exit 1
fi

echo "==> Build check complete: SUCCESS!"
exit 0
