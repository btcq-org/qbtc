```bash
## mainnet uses chain-id qbtc-1 (scripts/install.sh); a new network needs its
## own chain-id so claim proofs and attestations from another chain never apply
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

# genesis UTXO snapshot: with config/genesis.bin in place, write the SHA-256 of
# each of its chunks into genesis.json. Every node splits its genesis.bin the
# same way at InitChain, refuses one that does not match, and checks each chunk
# again before loading it (one chunk per block). Bitcoin blocks apply only
# after the last chunk. A genesis.bin without these hashes is refused.
./qbtcd genesis set-utxo-chunk-hashes config/genesis.bin
# publish genesis.json and genesis.bin, and list both in the release's
# sha256sum.txt, which scripts/install.sh checks them against

# governance fund addresses (string params), kept by export and import
jq --arg dev "<dev fund address>" --arg mkt "<marketing fund address>" \
   '.app_state.qbtc.string_params = [{"key":"DevFundAddress","value":$dev},{"key":"MarketingFundAddress","value":$mkt}]' \
   genesis.json > tmp.json && mv tmp.json genesis.json

# claims are off by default (ClaimWithProofDisabled = 1); governance enables
# them with MsgUpdateParam once the chain is ready

./qbtcd genesis validate-genesis
```

Once the snapshot has loaded (the `loaded genesis UTXO chunk` log line for
the last chunk), `config/genesis.bin` and `utxo_chunks/` in the node home may be
deleted to free disk; the node does not delete them, so a block executed
again after a crash still finds its chunk.

`qbtcd export --for-zero-height` is not supported; export at the last height.

## setup firewall
```bash
sudo ufw allow 26656/tcp
sudo ufw allow 26657/tcp
sudo ufw allow 1317/tcp
sudo ufw allow 30006/tcp
```