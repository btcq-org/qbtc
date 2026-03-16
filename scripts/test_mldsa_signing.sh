#!/bin/bash
# Test end-to-end MLDSA signing using the node's own CLI.
# This proves cloudflare/circl sign + verify works when both happen on the node side.
#
# Usage: ./scripts/test_mldsa_signing.sh
# Prerequisites: build/qbtcd must exist (run `make build` first)
#
# What this tests:
#   1. Creates a local single-node chain
#   2. Creates an MLDSA-44 key (using cloudflare/circl via cosmos-sdk)
#   3. Funds the MLDSA account
#   4. Signs and broadcasts a tx FROM the MLDSA account
#   5. If tx succeeds → circl sign+verify works end-to-end
#   6. If tx fails with "signature verification failed" → circl has internal issues too

set -eu

APPD=./build/qbtcd
HOME_DIR=$(mktemp -d)
CHAIN_ID="mldsa-test-1"
DENOM="qbtc"

cleanup() {
    echo "Cleaning up $HOME_DIR"
    rm -rf "$HOME_DIR"
}
trap cleanup EXIT

echo "=== QBTC MLDSA End-to-End Signing Test ==="
echo "Home: $HOME_DIR"
echo ""

# 1. Configure
echo "Step 1: Configuring node..."
$APPD config set client chain-id $CHAIN_ID --home $HOME_DIR
$APPD config set client keyring-backend test --home $HOME_DIR
$APPD config set client output json --home $HOME_DIR

# 2. Create validator key (secp256k1 - standard)
echo "Step 2: Creating validator key (secp256k1)..."
yes | $APPD keys add validator --home $HOME_DIR > /dev/null 2>&1
VALIDATOR=$($APPD keys show validator -a --home $HOME_DIR)
echo "  Validator: $VALIDATOR"

# 3. Create MLDSA key
echo "Step 3: Creating MLDSA-44 key..."
yes | $APPD keys add mldsa-user --algo mldsa44 --home $HOME_DIR > /dev/null 2>&1
MLDSA_ADDR=$($APPD keys show mldsa-user -a --home $HOME_DIR)
echo "  MLDSA user: $MLDSA_ADDR"

# 4. Initialize chain
echo "Step 4: Initializing chain..."
$APPD init test-node --chain-id $CHAIN_ID --home $HOME_DIR > /dev/null 2>&1
$APPD config set app minimum-gas-prices "0.0025$DENOM" --home $HOME_DIR

# 5. Fund both accounts in genesis
echo "Step 5: Setting up genesis..."
$APPD genesis add-genesis-account $VALIDATOR "1000000000000$DENOM" --home $HOME_DIR
$APPD genesis add-genesis-account $MLDSA_ADDR "1000000000$DENOM" --home $HOME_DIR
$APPD genesis gentx validator "1000000000$DENOM" --chain-id $CHAIN_ID --keyring-backend test --home $HOME_DIR > /dev/null 2>&1
$APPD genesis collect-gentxs --home $HOME_DIR > /dev/null 2>&1

# 6. Start node in background
echo "Step 6: Starting node..."
$APPD start --home $HOME_DIR > "$HOME_DIR/node.log" 2>&1 &
NODE_PID=$!

# Wait for node to start
echo "  Waiting for node to start (up to 30s)..."
for i in $(seq 1 30); do
    if $APPD query block --home $HOME_DIR > /dev/null 2>&1; then
        echo "  Node ready after ${i}s"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "  FAIL: Node did not start in time"
        echo "  Node log:"
        tail -20 "$HOME_DIR/node.log"
        kill $NODE_PID 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# 7. Check MLDSA account balance
echo "Step 7: Checking MLDSA account balance..."
BALANCE=$($APPD query bank balances $MLDSA_ADDR --home $HOME_DIR 2>/dev/null || echo "query failed")
echo "  Balance: $BALANCE"

# 8. Send transaction FROM MLDSA account (this is the actual test)
echo ""
echo "=== Step 8: Signing and broadcasting tx from MLDSA account ==="
echo "  This uses cloudflare/circl for BOTH signing and verification"
echo ""

TX_RESULT=$($APPD tx bank send mldsa-user $VALIDATOR "1000$DENOM" \
    --chain-id $CHAIN_ID \
    --keyring-backend test \
    --home $HOME_DIR \
    --gas 200000 \
    --fees "7500$DENOM" \
    --yes \
    --output json 2>&1) || true

echo "TX Result:"
echo "$TX_RESULT" | head -20

# Parse result
TX_CODE=$(echo "$TX_RESULT" | grep -o '"code":[0-9]*' | head -1 | cut -d: -f2 || echo "unknown")

echo ""
if [ "$TX_CODE" = "0" ]; then
    echo "=== SUCCESS ==="
    echo "MLDSA-44 signing works end-to-end with cloudflare/circl."
    echo "The issue is confirmed: vscore TSS signatures are NOT compatible with circl verification."
elif echo "$TX_RESULT" | grep -q "signature verification failed"; then
    echo "=== FAIL: Signature verification failed ==="
    echo "Even the node's own circl-based signing fails verification."
    echo "This would indicate a bug in the cosmos-sdk MLDSA integration."
else
    echo "=== RESULT: code=$TX_CODE ==="
    echo "Check the output above for details."
fi

# Cleanup
kill $NODE_PID 2>/dev/null || true
wait $NODE_PID 2>/dev/null || true
