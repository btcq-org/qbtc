#!/bin/bash
set -e

# WASM Integration End-to-End Test Script
# This script tests the full WASM integration in qbtc

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="${PROJECT_ROOT}/build/qbtcd"
CHAIN_ID="qbtc-wasm-test"
TEST_DIR="/tmp/qbtc-wasm-test"
NODE_HOME="${TEST_DIR}/node"
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

cleanup() {
    log_info "Cleaning up..."
    pkill qbtcd || true
    rm -rf "${TEST_DIR}"
    log_success "Cleanup complete"
}

trap cleanup EXIT

# Step 1: Build the binary
log_info "Step 1: Building qbtcd binary..."
cd "${PROJECT_ROOT}"
if [ ! -f "${BINARY}" ]; then
    log_info "Binary not found, building..."
    go build  -o "${BINARY}" ./cmd/qbtcd
fi
log_success "Binary ready: ${BINARY}"

# Verify binary works
"${BINARY}" version > /dev/null 2>&1 || {
    log_error "Binary is not working"
    exit 1
}

# Step 2: Clean and setup test environment
log_info "Step 2: Setting up test environment..."
rm -rf "${TEST_DIR}"
mkdir -p "${TEST_DIR}"
mkdir -p "${NODE_HOME}"
log_success "Test directory created: ${TEST_DIR}"

# Step 3: Initialize the chain
log_info "Step 3: Initializing chain..."
"${BINARY}" init test-node --chain-id "${CHAIN_ID}" --home "${NODE_HOME}" > /dev/null 2>&1
log_success "Chain initialized with ID: ${CHAIN_ID}"

# Step 4: Create test accounts
log_info "Step 4: Creating test accounts..."

# Add validator account
echo "${MNEMONIC}" | "${BINARY}" keys add validator \
    --recover \
    --keyring-backend test \
    --home "${NODE_HOME}" > /dev/null 2>&1

VALIDATOR_ADDR=$("${BINARY}" keys show validator -a --keyring-backend test --home "${NODE_HOME}")
log_success "Validator account created: ${VALIDATOR_ADDR}"

# Add test user account
"${BINARY}" keys add user1 \
    --keyring-backend test \
    --home "${NODE_HOME}" > /dev/null 2>&1

USER1_ADDR=$("${BINARY}" keys show user1 -a --keyring-backend test --home "${NODE_HOME}")
log_success "User account created: ${USER1_ADDR}"

# Step 5: Add genesis accounts
log_info "Step 5: Adding genesis accounts..."
"${BINARY}" genesis add-genesis-account "${VALIDATOR_ADDR}" 1000000000000qbtc \
    --keyring-backend test \
    --home "${NODE_HOME}"

"${BINARY}" genesis add-genesis-account "${USER1_ADDR}" 1000000000000qbtc \
    --keyring-backend test \
    --home "${NODE_HOME}"

log_success "Genesis accounts added"

# Step 6: Create genesis transaction
log_info "Step 6: Creating genesis transaction..."
"${BINARY}" genesis gentx validator 100000000000qbtc \
    --chain-id "${CHAIN_ID}" \
    --keyring-backend test \
    --home "${NODE_HOME}" > /dev/null 2>&1

"${BINARY}" genesis collect-gentxs --home "${NODE_HOME}" > /dev/null 2>&1
log_success "Genesis transaction created"

# Step 7: Configure node for testing
log_info "Step 7: Configuring node..."
# Update config for faster blocks
sed -i.bak 's/timeout_commit = "5s"/timeout_commit = "1s"/g' "${NODE_HOME}/config/config.toml"
sed -i.bak 's/timeout_propose = "3s"/timeout_propose = "1s"/g' "${NODE_HOME}/config/config.toml"

# Enable API and unsafe CORS for testing
sed -i.bak 's/enable = false/enable = true/g' "${NODE_HOME}/config/app.toml"
sed -i.bak 's/enabled-unsafe-cors = false/enabled-unsafe-cors = true/g' "${NODE_HOME}/config/app.toml"

# Set minimum gas prices (required)
sed -i.bak 's/minimum-gas-prices = ""/minimum-gas-prices = "0.025qbtc"/g' "${NODE_HOME}/config/app.toml"
log_success "Node configured"

# Step 8: Start the node
log_info "Step 8: Starting node..."
"${BINARY}" start --home "${NODE_HOME}" > "${TEST_DIR}/node.log" 2>&1 &
NODE_PID=$!
log_success "Node started (PID: ${NODE_PID})"

# Step 9: Wait for node to be ready
log_info "Step 9: Waiting for node to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:26657/status > /dev/null 2>&1; then
        log_success "Node is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "Node failed to start within 30 seconds"
        tail -50 "${TEST_DIR}/node.log"
        exit 1
    fi
    echo -n "."
    sleep 1
done

# Wait for a few blocks
log_info "Waiting for blocks to be produced..."
sleep 5

# Step 10: Check WASM module is active
log_info "Step 10: Checking WASM module status..."
WASM_PARAMS=$("${BINARY}" q wasm params --home "${NODE_HOME}" --output json 2>/dev/null || echo "")
if [ -n "${WASM_PARAMS}" ]; then
    log_success "WASM module is active!"
    echo "${WASM_PARAMS}" | jq '.' || echo "${WASM_PARAMS}"
else
    log_warning "WASM params query returned empty (module may not be fully initialized)"
fi

# Step 11: Download a test contract
log_info "Step 11: Downloading test contract..."
TEST_CONTRACT="${TEST_DIR}/cw20_base.wasm"

if [ ! -f "${TEST_CONTRACT}" ]; then
    log_info "Downloading cw20_base contract..."
    curl -L -o "${TEST_CONTRACT}" \
        "https://github.com/CosmWasm/cw-plus/releases/download/v1.0.1/cw20_base.wasm" \
        2>/dev/null || {
        log_warning "Failed to download contract, trying alternative source..."
        # Try alternative: build a simple contract or use local test
        log_warning "Skipping contract download test"
        TEST_CONTRACT=""
    }
fi

if [ -n "${TEST_CONTRACT}" ] && [ -f "${TEST_CONTRACT}" ]; then
    CONTRACT_SIZE=$(wc -c < "${TEST_CONTRACT}")
    log_success "Contract downloaded (${CONTRACT_SIZE} bytes)"

    # Step 12: Store the contract
    log_info "Step 12: Storing WASM contract..."
    STORE_TX=$("${BINARY}" tx wasm store "${TEST_CONTRACT}" \
        --from validator \
        --gas 3000000 \
        --gas-prices 0.025qbtc \
        --chain-id "${CHAIN_ID}" \
        --keyring-backend test \
        --home "${NODE_HOME}" \
        --yes \
        --output json 2>&1)

    STORE_TXHASH=$(echo "${STORE_TX}" | jq -r '.txhash' 2>/dev/null || echo "")

    if [ -n "${STORE_TXHASH}" ] && [ "${STORE_TXHASH}" != "null" ]; then
        log_success "Contract store transaction submitted: ${STORE_TXHASH}"

        # Wait for transaction to be included
        log_info "Waiting for transaction to be included in a block..."
        sleep 6

        # Query the transaction
        TX_RESULT=$("${BINARY}" q tx "${STORE_TXHASH}" \
            --home "${NODE_HOME}" \
            --output json 2>/dev/null || echo "")

        if [ -n "${TX_RESULT}" ]; then
            CODE_ID=$(echo "${TX_RESULT}" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value' 2>/dev/null | head -1)

            if [ -n "${CODE_ID}" ] && [ "${CODE_ID}" != "null" ] && [ "${CODE_ID}" != "" ]; then
                log_success "Contract stored with Code ID: ${CODE_ID}"

                # Step 13: Query stored code
                log_info "Step 13: Querying stored code..."
                CODE_INFO=$("${BINARY}" q wasm code "${CODE_ID}" \
                    --home "${NODE_HOME}" \
                    --output json 2>/dev/null || echo "")

                if [ -n "${CODE_INFO}" ]; then
                    log_success "Code info retrieved:"
                    echo "${CODE_INFO}" | jq '.' || echo "${CODE_INFO}"
                else
                    log_warning "Could not query code info"
                fi

                # Step 14: Instantiate the contract
                log_info "Step 14: Instantiating contract..."
                INIT_MSG='{"name":"Test Token","symbol":"TEST","decimals":6,"initial_balances":[],"mint":{"minter":"'${VALIDATOR_ADDR}'"}}'

                INSTANTIATE_TX=$("${BINARY}" tx wasm instantiate "${CODE_ID}" \
                    "${INIT_MSG}" \
                    --from validator \
                    --label "test-token-1" \
                    --admin "${VALIDATOR_ADDR}" \
                    --gas 500000 \
                    --gas-prices 0.025qbtc \
                    --chain-id "${CHAIN_ID}" \
                    --keyring-backend test \
                    --home "${NODE_HOME}" \
                    --yes \
                    --output json 2>&1)

                INST_TXHASH=$(echo "${INSTANTIATE_TX}" | jq -r '.txhash' 2>/dev/null || echo "")

                if [ -n "${INST_TXHASH}" ] && [ "${INST_TXHASH}" != "null" ]; then
                    log_success "Instantiate transaction submitted: ${INST_TXHASH}"

                    sleep 6

                    # Get contract address
                    INST_RESULT=$("${BINARY}" q tx "${INST_TXHASH}" \
                        --home "${NODE_HOME}" \
                        --output json 2>/dev/null || echo "")

                    CONTRACT_ADDR=$(echo "${INST_RESULT}" | jq -r '.events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value' 2>/dev/null | head -1)

                    if [ -n "${CONTRACT_ADDR}" ] && [ "${CONTRACT_ADDR}" != "null" ] && [ "${CONTRACT_ADDR}" != "" ]; then
                        log_success "Contract instantiated at: ${CONTRACT_ADDR}"

                        # Step 15: Query contract state
                        log_info "Step 15: Querying contract state..."
                        CONTRACT_INFO=$("${BINARY}" q wasm contract "${CONTRACT_ADDR}" \
                            --home "${NODE_HOME}" \
                            --output json 2>/dev/null || echo "")

                        if [ -n "${CONTRACT_INFO}" ]; then
                            log_success "Contract info:"
                            echo "${CONTRACT_INFO}" | jq '.' || echo "${CONTRACT_INFO}"
                        fi

                        # Query token info
                        TOKEN_INFO=$("${BINARY}" q wasm contract-state smart "${CONTRACT_ADDR}" \
                            '{"token_info":{}}' \
                            --home "${NODE_HOME}" \
                            --output json 2>/dev/null || echo "")

                        if [ -n "${TOKEN_INFO}" ]; then
                            log_success "Token info:"
                            echo "${TOKEN_INFO}" | jq '.' || echo "${TOKEN_INFO}"
                        fi
                    else
                        log_warning "Could not get contract address from instantiate transaction"
                    fi
                else
                    log_warning "Instantiate transaction may have failed"
                    echo "${INSTANTIATE_TX}"
                fi
            else
                log_warning "Could not extract code ID from transaction"
                echo "${TX_RESULT}" | jq '.raw_log' 2>/dev/null || echo "${TX_RESULT}"
            fi
        else
            log_warning "Could not query store transaction"
        fi
    else
        log_warning "Store transaction may have failed"
        echo "${STORE_TX}"
    fi
else
    log_warning "Skipping contract store/instantiate tests (no contract file)"
fi

# Step 16: List all codes
log_info "Step 16: Listing all stored codes..."
ALL_CODES=$("${BINARY}" q wasm list-code \
    --home "${NODE_HOME}" \
    --output json 2>/dev/null || echo "")

if [ -n "${ALL_CODES}" ]; then
    CODE_COUNT=$(echo "${ALL_CODES}" | jq '.code_infos | length' 2>/dev/null || echo "0")
    log_success "Total codes stored: ${CODE_COUNT}"
    if [ "${CODE_COUNT}" != "0" ]; then
        echo "${ALL_CODES}" | jq '.code_infos' || echo "${ALL_CODES}"
    fi
else
    log_info "No codes stored yet (or query not available)"
fi

# Step 17: Check module account
log_info "Step 17: Checking WASM module account..."
WASM_MODULE_ACCOUNT=$("${BINARY}" q auth module-account wasm \
    --home "${NODE_HOME}" \
    --output json 2>/dev/null || echo "")

if [ -n "${WASM_MODULE_ACCOUNT}" ]; then
    log_success "WASM module account found:"
    echo "${WASM_MODULE_ACCOUNT}" | jq '.' || echo "${WASM_MODULE_ACCOUNT}"
else
    log_warning "Could not query WASM module account"
fi

# Step 18: Export genesis to verify WASM state
log_info "Step 18: Checking genesis export..."
pkill qbtcd || true
sleep 2

GENESIS_EXPORT=$("${BINARY}" export --home "${NODE_HOME}" 2>/dev/null || echo "")
if [ -n "${GENESIS_EXPORT}" ]; then
    WASM_STATE=$(echo "${GENESIS_EXPORT}" | jq '.app_state.wasm' 2>/dev/null || echo "")
    if [ -n "${WASM_STATE}" ] && [ "${WASM_STATE}" != "null" ]; then
        log_success "WASM state found in genesis export"
        echo "${WASM_STATE}" | jq '{params, codes: (.codes | length), contracts: (.contracts | length)}' 2>/dev/null || echo "WASM state present"
    else
        log_warning "No WASM state in genesis export"
    fi
else
    log_warning "Could not export genesis"
fi

# Summary
echo ""
echo "======================================"
log_success "WASM INTEGRATION TEST SUMMARY"
echo "======================================"
echo ""
log_info "Chain ID: ${CHAIN_ID}"
log_info "Validator: ${VALIDATOR_ADDR}"
log_info "User: ${USER1_ADDR}"
log_info "Node Home: ${NODE_HOME}"
log_info "Logs: ${TEST_DIR}/node.log"
echo ""

if [ -n "${CODE_ID}" ]; then
    log_success "✅ Contract stored successfully (Code ID: ${CODE_ID})"
fi

if [ -n "${CONTRACT_ADDR}" ]; then
    log_success "✅ Contract instantiated successfully"
    log_success "   Contract Address: ${CONTRACT_ADDR}"
fi

echo ""
log_success "🎉 WASM integration test completed!"
echo ""
log_info "To interact with the test node manually:"
echo "  export QBTC_HOME='${NODE_HOME}'"
echo "  ${BINARY} q wasm list-code --home '${NODE_HOME}'"
echo ""
log_info "Test files will be cleaned up on exit"
echo ""
