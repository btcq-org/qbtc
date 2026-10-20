```bash
./qbtcd config set client chain-id qbtc-testnet

./qbtcd init qbtc --chain-id qbtc-testnet
## set minimum gas price
./qbtcd config set app minimum-gas-prices 0.000qbtc

## mint 50 qbtc to genesis node
./qbtcd genesis add-genesis-account qbtc-init-validator "5000000000qbtc"

# add validator
./qbtcd genesis gentx qbtc-init-validator 1000000000qbtc --chain-id qbtc-testnet

./qbtcd genesis collect-gentxs

./qbtcd genesis validate-genesis

# generate verify key / setup key
# https://sgp1.vultrobjects.com/genesis/genesis-931372.bin
# https://sgp1.vultrobjects.com/genesis/circuit.cs
# https://sgp1.vultrobjects.com/genesis/proving.key
# https://sgp1.vultrobjects.com/genesis/verifying.key
# update genesis file to include verify key
jq --arg key "$(cat output.txt)" '.app_state.qbtc.zk_verifying_key = $key' genesis.json > tmp.json

# set the Bitcoin anchor: START is the first Bitcoin height the chain processes,
# and the anchor is the block before it (see docs/BTC_BLOCK_INGESTION.md)
START=<first bitcoin height>
ANCHOR=$((START - 1))
HEADER_HEX=$(bitcoin-cli getblockheader "$(bitcoin-cli getblockhash $ANCHOR)" false)
PERIOD_START_TIME=$(bitcoin-cli getblockheader "$(bitcoin-cli getblockhash $((ANCHOR - ANCHOR % 2016)))" | jq .time)
jq --arg start "$START" \
   --arg header "$(echo -n "$HEADER_HEX" | xxd -r -p | base64)" \
   --argjson period "$PERIOD_START_TIME" \
   '.app_state.qbtc.btc_initial_height = $start
    | .app_state.qbtc.btc_anchor_header = $header
    | .app_state.qbtc.btc_anchor_period_start_time = $period' tmp.json > genesis.json

./qbtcd genesis validate-genesis
```

## setup firewall
```bash
sudo ufw allow 26656/tcp
sudo ufw allow 26657/tcp
sudo ufw allow 1317/tcp
sudo ufw allow 30006/tcp
```