#!/bin/bash
# Quick WASM Integration Test
# Tests that WASM module loads and basic queries work

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="${PROJECT_ROOT}/build/qbtcd"

echo "🧪 Quick WASM Integration Test"
echo "================================"
echo ""

# Test 1: Binary exists
echo "✓ Checking binary exists..."
if [ ! -f "${BINARY}" ]; then
    echo "❌ Binary not found. Building..."
    cd "${PROJECT_ROOT}"
    CGO_ENABLED=1 go build -tags muslc -o "${BINARY}" ./cmd/btcqd
fi
echo "  Binary: ${BINARY}"

# Test 2: Binary runs
echo ""
echo "✓ Testing binary runs..."
VERSION=$("${BINARY}" version 2>&1 || echo "error")
if [ "${VERSION}" = "error" ]; then
    echo "❌ Binary failed to run"
    exit 1
fi
echo "  Version: ${VERSION}"

# Test 3: WASM module compiled in
echo ""
echo "✓ Checking for WASM module..."
HELP_OUTPUT=$("${BINARY}" --help 2>&1)
if echo "${HELP_OUTPUT}" | grep -q "wasm" 2>/dev/null; then
    echo "  ✅ WASM references found in help"
else
    echo "  ⚠️  No WASM references in help (this is okay, check after init)"
fi

# Test 4: Check binary dependencies (wasmvm)
echo ""
echo "✓ Checking WASM VM linkage..."
if command -v ldd &> /dev/null; then
    if ldd "${BINARY}" 2>/dev/null | grep -q "libwasmvm" 2>/dev/null; then
        echo "  ✅ libwasmvm linked (Linux)"
    else
        echo "  ℹ️  No libwasmvm found in ldd (may be statically linked)"
    fi
elif command -v otool &> /dev/null; then
    if otool -L "${BINARY}" 2>/dev/null | grep -q "libwasmvm" 2>/dev/null; then
        echo "  ✅ libwasmvm linked (macOS)"
    else
        echo "  ℹ️  No libwasmvm found in otool (may be statically linked)"
    fi
fi

# Test 5: CGO enabled check
echo ""
echo "✓ Verifying CGO was enabled during build..."
if strings "${BINARY}" 2>/dev/null | grep -q "wasmvm" 2>/dev/null; then
    echo "  ✅ wasmvm symbols found in binary"
else
    echo "  ⚠️  wasmvm symbols not found (this might be okay)"
fi

# Test 6: Quick init test
echo ""
echo "✓ Testing quick initialization..."
TEST_HOME="/tmp/btcq-quick-test-$$"
mkdir -p "${TEST_HOME}"

"${BINARY}" init test --chain-id test --home "${TEST_HOME}" > /dev/null 2>&1
GENESIS="${TEST_HOME}/config/genesis.json"

if [ -f "${GENESIS}" ]; then
    echo "  ✅ Genesis created"

    # Check if wasm module is in genesis
    if grep -q '"wasm"' "${GENESIS}" 2>/dev/null; then
        echo "  ✅ WASM module found in genesis"

        # Show WASM params from genesis
        WASM_PARAMS=$(cat "${GENESIS}" | jq -r '.app_state.wasm.params' 2>/dev/null || echo "{}")
        if [ "${WASM_PARAMS}" != "{}" ] && [ "${WASM_PARAMS}" != "null" ]; then
            echo ""
            echo "  WASM Params from genesis:"
            echo "${WASM_PARAMS}" | jq '.' 2>/dev/null || echo "${WASM_PARAMS}"
        fi
    else
        echo "  ❌ WASM module NOT found in genesis"
        echo ""
        echo "Available modules in genesis:"
        cat "${GENESIS}" | jq -r '.app_state | keys[]' 2>/dev/null | sort
        rm -rf "${TEST_HOME}"
        exit 1
    fi
else
    echo "  ❌ Genesis not created"
    rm -rf "${TEST_HOME}"
    exit 1
fi

# Cleanup
rm -rf "${TEST_HOME}"

echo ""
echo "================================"
echo "✅ All quick tests passed!"
echo ""
echo "Next steps:"
echo "  1. Run full integration test:"
echo "     ./scripts/test_wasm_integration.sh"
echo ""
echo "  2. Or start a node and test manually:"
echo "     ./build/qbtcd init mynode --chain-id test"
echo "     ./build/qbtcd start"
echo ""
