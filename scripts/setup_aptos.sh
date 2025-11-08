#!/bin/bash

set -e 

echo "[*] Aptos Move Compilation and Fuzzing Script"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Parse command line arguments
CONTRACT_NAME="aptos-demo"
TIMEOUT_DURATION=20
DO_BUILD=true

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -c, --contract NAME    Contract name to fuzz (default: aptos-demo)"
    echo "                         Available: aptos-demo, fuzzing-demo"
    echo "  -t, --timeout SECONDS  Timeout duration for fuzzing (default: 20)"
    echo "  -n, --no-build         Use prebuilt binary; do not build"
    echo "  -h, --help             Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Use default aptos-demo"
    echo "  $0 -c fuzzing-demo                    # Fuzz the fuzzing-demo contract"
    echo "  $0 -c fuzzing-demo -t 60              # Fuzz for 60 seconds"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--contract)
            CONTRACT_NAME="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT_DURATION="$2"
            shift 2
            ;;
        -n|--no-build)
            DO_BUILD=false
            shift 1
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "[-] Unknown option: $1"
            usage
            ;;
    esac
done

# Module Path
CONTRACT_DIR="$PROJECT_ROOT/contracts/$CONTRACT_NAME"
LIBAFL_APTOS_BIN="$PROJECT_ROOT/target/release/libafl-aptos"

echo "[*] Project root: $PROJECT_ROOT"
echo "[*] Contract name: $CONTRACT_NAME"
echo "[*] Contract directory: $CONTRACT_DIR"
echo "[*] Fuzzing timeout: ${TIMEOUT_DURATION}s"

# Check if aptos CLI is available
if ! command -v aptos &> /dev/null; then
    echo "[-] Error: aptos CLI not found. Please install it first."
    echo "[*] You can install it with: curl -fsSL \"https://aptos.dev/scripts/install_cli.sh\" | sh"
    exit 1
fi

# Check if contract directory exists
if [[ ! -d "$CONTRACT_DIR" ]]; then
    echo "[-] Error: Contract directory not found: $CONTRACT_DIR"
    echo "[*] Available contracts in $PROJECT_ROOT/contracts/:"
    ls -1 "$PROJECT_ROOT/contracts/" 2>/dev/null || echo "  (none)"
    exit 1
fi

echo "[+] Step 1: Preparing libafl-aptos binary..."
cd "$PROJECT_ROOT"
if [[ "$DO_BUILD" == true ]]; then
    echo "[*] Building (release) libafl-aptos..."
    cargo build --release --bin libafl-aptos
    if [[ ! -f "$LIBAFL_APTOS_BIN" ]]; then
        echo "[-] Error: libafl-aptos binary not found after build: $LIBAFL_APTOS_BIN"
        exit 1
    fi
else
    echo "[*] Skipping build; using prebuilt binary if available"
    BIN_RELEASE="$PROJECT_ROOT/target/release/libafl-aptos"
    BIN_DEBUG="$PROJECT_ROOT/target/debug/libafl-aptos"
    if [[ -x "$BIN_RELEASE" ]]; then
        LIBAFL_APTOS_BIN="$BIN_RELEASE"
    elif [[ -x "$BIN_DEBUG" ]]; then
        LIBAFL_APTOS_BIN="$BIN_DEBUG"
    else
        echo "[-] Error: prebuilt libafl-aptos binary not found."
        echo "[*] Build it first, e.g.: cargo build --release --bin libafl-aptos"
        exit 1
    fi
fi

echo "[+] Step 2: Compiling $CONTRACT_NAME contract..."
cd "$CONTRACT_DIR"

# Clean previous build artifacts
if [[ -d "build" ]]; then
    echo "[*] Cleaning previous build artifacts..."
    rm -rf build
fi

# Compile with all artifacts
echo "[*] Running: aptos move compile --included-artifacts all"
aptos move compile --included-artifacts all

# Check if compilation was successful
if [[ ! -d "build" ]]; then
    echo "[-] Error: Compilation failed - build directory not created"
    exit 1
fi

echo "[+] Step 3: Detecting artifact paths..."

# Detect module name from build artifacts
BUILD_DIR="$CONTRACT_DIR/build"
if [[ ! -d "$BUILD_DIR" ]]; then
    echo "[-] Error: Build directory not found: $BUILD_DIR"
    exit 1
fi

# Find all .mv files in bytecode_modules (excluding dependencies)
mapfile -t MODULE_FILES < <(find "$BUILD_DIR" -path "*/bytecode_modules/*.mv" -not -path "*/dependencies/*" | sort)
if [[ ${#MODULE_FILES[@]} -eq 0 ]]; then
    echo "[-] Error: No module files found in $BUILD_DIR"
    exit 1
fi

# Find the ABI directory
ABI_PATH=$(find "$BUILD_DIR" -type d -name "abis" -not -path "*/dependencies/*" | head -n 1)
if [[ -z "$ABI_PATH" ]]; then
    echo "[-] Warning: No ABI directory found in $BUILD_DIR; fuzzing will be skipped."
fi

echo "[*] Found ${#MODULE_FILES[@]} module(s)" 
echo "[*] ABI path: ${ABI_PATH:-<none>}"

# Verify ABI path exists when provided
if [[ -n "$ABI_PATH" && ! -d "$ABI_PATH" ]]; then
    echo "[-] Warning: ABI directory path $ABI_PATH is not accessible; skipping fuzzing."
    ABI_PATH=""
fi

echo "[+] Step 4: Running libafl-aptos fuzzer for each module..."
cd "$PROJECT_ROOT"

for MODULE_PATH in "${MODULE_FILES[@]}"; do
    if [[ ! -f "$MODULE_PATH" ]]; then
        echo "[-] Warning: Skipping missing module file $MODULE_PATH"
        continue
    fi

    echo ""
    echo "[*] Fuzzing module: $MODULE_PATH"

    if [[ -z "$ABI_PATH" ]]; then
        echo "[*] Command: $LIBAFL_APTOS_BIN --module-path \"$MODULE_PATH\" --timeout $TIMEOUT_DURATION"
        "$LIBAFL_APTOS_BIN" --module-path "$MODULE_PATH" --timeout "$TIMEOUT_DURATION"
    else
        echo "[*] Command: $LIBAFL_APTOS_BIN --module-path \"$MODULE_PATH\" --abi-path \"$ABI_PATH\" --timeout $TIMEOUT_DURATION"
        "$LIBAFL_APTOS_BIN" --module-path "$MODULE_PATH" --abi-path "$ABI_PATH" --timeout "$TIMEOUT_DURATION"
    fi
done

echo ""
echo "[+] Fuzzing completed for all modules"
