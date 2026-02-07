# Binary name
BINARY_NAME=gdpr-scan
ENTRY_POINT=cmd/scanner/main.go

# Build directory
BUILD_DIR=bin

.PHONY: all build-all build-linux build-windows clean

all: build-all

build-all: build-linux build-windows

build-linux:
	@echo "Building for Linux (amd64)..."
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(ENTRY_POINT)
	@echo "Linux build complete: $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

build-windows:
	@echo "Building for Windows (amd64)..."
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(ENTRY_POINT)
	@echo "Windows build complete: $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe"

clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete."
