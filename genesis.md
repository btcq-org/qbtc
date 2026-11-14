```bash
./qbtcd config set client chain-id qbtc-testnet

## the chain accepts ML-DSA-65 keys only: `init` writes
## consensus_params.validator.pub_key_types = ["ml_dsa_65"] and creates an
## ML-DSA-65 consensus key, and `keys add` creates ML-DSA-65 account keys
## (both are the defaults; --consensus-key-algo / --algo accept nothing else)
./qbtcd init qbtc --chain-id qbtc-testnet --consensus-key-algo ml_dsa_65
./qbtcd keys add qbtc-init-validator --algo ml_dsa_65
## init also writes consensus_params.block.max_gas = 100000000 and
## minimum-gas-prices = "0.0025qbtc" in app.toml; claims pay no fee

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
# every step below edits the genesis file in the node home, the same file
# init, gentx and collect-gentxs wrote (use your --home if it is not the default)
GENESIS="$HOME/.qbtc/config/genesis.json"

# update genesis file to include verify key
jq --arg key "$(cat output.txt)" '.app_state.qbtc.zk_verifying_key = $key' "$GENESIS" > tmp.json && mv tmp.json "$GENESIS"

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
    | .app_state.qbtc.btc_anchor_period_start_time = $period' "$GENESIS" > tmp.json && mv tmp.json "$GENESIS"

# genesis UTXO snapshot: with config/genesis.bin in place in the node home,
# write the SHA-256 of each of its chunks into $GENESIS. Every node splits its
# genesis.bin the same way at InitChain, refuses one that does not match, and
# checks each chunk again before loading it (one chunk per block). Bitcoin
# blocks apply only after the last chunk. A genesis.bin without these hashes is
# refused.
./qbtcd genesis set-utxo-chunk-hashes

./qbtcd genesis validate-genesis
```

`config/genesis.bin` and `utxo_chunks/` in the node home may be deleted to free
disk once the snapshot has loaded and that is committed: wait for the
`loaded genesis UTXO chunk` log line of the last chunk, then for the node to
commit a later block. The line is logged while its block executes; a node that
stops before that block commits executes it again and needs the chunk file. The
node never deletes them itself.

## setup firewall
```bash
sudo ufw allow 26656/tcp
sudo ufw allow 26657/tcp
sudo ufw allow 1317/tcp
sudo ufw allow 30006/tcp
```