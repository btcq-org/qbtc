#!/usr/bin/env bash
# Runs a 4-validator qbtc chain in Docker (docker-compose.yml at the repo root)
# that follows Bitcoin mainnet, from your own Bitcoin node or, without one,
# through the Esplora-backed proxy from tests/vetest. `make localnet` calls it.
#
#   scripts/localnet.sh up      # generate .testnets/ (first time) and start the network
#   scripts/localnet.sh status  # chain height and last processed Bitcoin block per validator
#   scripts/localnet.sh down    # stop the network, keep .testnets/
#   scripts/localnet.sh clean   # stop the network and delete .testnets/
#
# Environment for `up`, read when .testnets/ is generated:
#   BITCOIN_RPC_HOST/PORT/USER/PASSWORD  your Bitcoin mainnet node (localhost works);
#                        without a host the btc-proxy service serves mainnet from BTC_UPSTREAM
#   BTC_UPSTREAM         proxy upstream (default esplora:https://mempool.space/api)
#   BTC_INITIAL_HEIGHT   first Bitcoin height the chain processes (default: the tip minus
#                        CONFIRMATION_DEPTH, so the first blocks are attested right away)
#   GENESIS_BIN          optional UTXO snapshot (genesis.md); then BTC_INITIAL_HEIGHT is
#                        required and is the height after the snapshot's
#   GENESIS_UTXO         UTXOs to put in genesis with their amount as entitlement, for
#                        claim tests: txid:vout:amount_sats:address, comma separated
#                        (P2WPKH bc1q... or P2PKH 1...); genesis then also carries the ZK
#                        verifying key ZK_VERIFYING_KEY (default: the vetest cache's)
#   CONFIRMATION_DEPTH   confirmations before a block is attested (default 6)
#   CHAIN_ID             default qbtc-localnet
#   QBTC_IMAGE           default btcq-org/qbtc:localnet, built by `make docker-localnet`
# Read on every `up`:
#   RPC_PORT_i, API_PORT_i, GRPC_PORT_i   host ports of validator i (0-3), when the
#                        defaults 26657-3i, 1317-i and 9090-2i are taken on this host
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="$ROOT/.testnets"
ENV_FILE="$NET/localnet.env"
DEFAULT_IMAGE=btcq-org/qbtc:localnet
IMAGE=${QBTC_IMAGE:-$DEFAULT_IMAGE}
CHAIN_ID=${CHAIN_ID:-qbtc-localnet}
DEPTH=${CONFIRMATION_DEPTH:-6}
PROXY_PORT=18449
PROXY_CONTROL=18450
VETEST_LIB="$ROOT/tests/vetest/vetest_lib.py"
DEFAULT_RPC_PORTS=(26657 26654 26651 26648)
DEFAULT_API_PORTS=(1317 1316 1315 1314)
DEFAULT_GRPC_PORTS=(9090 9088 9086 9084)

log() { echo "localnet: $*"; }
die() { echo "localnet: $*" >&2; exit 1; }

# host_port RPC|API|GRPC <i>: the validator's host port, from <KIND>_PORT_<i> or the default
host_port() {
  local var="$1_PORT_$2" defaults="DEFAULT_$1_PORTS[$2]"
  echo "${!var:-${!defaults}}"
}

# record_ports: keeps the *_PORT_i variables set for this run in the env file,
# so docker compose and `status` see the same host ports
record_ports() {
  local kind i var
  [ -f "$ENV_FILE" ] || return 0
  sed -i '/^\(RPC\|API\|GRPC\)_PORT_[0-3]=/d' "$ENV_FILE"
  for kind in RPC API GRPC; do
    for i in 0 1 2 3; do
      var="${kind}_PORT_$i"
      [ -n "${!var:-}" ] && echo "$var=${!var}" >> "$ENV_FILE"
    done
  done
  return 0
}

load_ports() {
  [ -f "$ENV_FILE" ] || return 0
  local line
  while IFS= read -r line; do
    case "$line" in
      RPC_PORT_[0-3]=* | API_PORT_[0-3]=* | GRPC_PORT_[0-3]=*) export "$line" ;;
    esac
  done < "$ENV_FILE"
}

compose() {
  local args=(-f "$ROOT/docker-compose.yml")
  if [ -f "$ENV_FILE" ]; then
    args+=(--env-file "$ENV_FILE")
    grep -q '^COMPOSE_PROFILES=proxy$' "$ENV_FILE" && args+=(--profile proxy)
  fi
  docker compose "${args[@]}" "$@"
}

# btc_rpc <url> <user:password or ""> <method> [params JSON]: prints the result
btc_rpc() {
  local url=$1 auth=$2 method=$3 params=${4:-[]}
  curl -sf --max-time 60 ${auth:+-u "$auth"} -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"1.0\",\"id\":\"localnet\",\"method\":\"$method\",\"params\":$params}" "$url" |
    python3 -c 'import json, sys
r = json.load(sys.stdin)
if r.get("error"):
    sys.exit("rpc error: %s" % r["error"])
print(r["result"])'
}

ensure_image() {
  docker image inspect "$IMAGE" >/dev/null 2>&1 && return
  [ "$IMAGE" = "$DEFAULT_IMAGE" ] || die "image $IMAGE not found"
  log "building $IMAGE (make docker-localnet)"
  (cd "$ROOT" && make docker-localnet)
}

generate() {
  local gen_host gen_port gen_user gen_pass node_host rpc_url rpc_auth network=()
  mkdir -p "$NET"
  {
    echo "QBTC_IMAGE=$IMAGE"
    if [ -z "${BITCOIN_RPC_HOST:-}" ]; then
      echo "COMPOSE_PROFILES=proxy"
      echo "BTC_UPSTREAM=${BTC_UPSTREAM:-esplora:https://mempool.space/api}"
    fi
  } > "$ENV_FILE"

  if [ -n "${BITCOIN_RPC_HOST:-}" ]; then
    gen_port=${BITCOIN_RPC_PORT:-8332}
    gen_user=${BITCOIN_RPC_USER:?BITCOIN_RPC_USER is required with BITCOIN_RPC_HOST}
    gen_pass=${BITCOIN_RPC_PASSWORD:?BITCOIN_RPC_PASSWORD is required with BITCOIN_RPC_HOST}
    case "$BITCOIN_RPC_HOST" in
      localhost | 127.0.0.1) node_host=host.docker.internal ;;
      *) node_host=$BITCOIN_RPC_HOST ;;
    esac
    gen_host=$node_host
    rpc_url="http://$BITCOIN_RPC_HOST:$gen_port"
    rpc_auth="$gen_user:$gen_pass"
    log "Bitcoin node: $rpc_url"
  else
    log "no BITCOIN_RPC_HOST: starting the btc-proxy service (upstream $(grep '^BTC_UPSTREAM=' "$ENV_FILE" | cut -d= -f2-))"
    compose up -d btc-proxy >/dev/null
    local i
    for i in $(seq 1 60); do
      curl -sf --max-time 5 "http://127.0.0.1:$PROXY_CONTROL/tip" >/dev/null 2>&1 && break
      [ "$i" -lt 60 ] || die "the btc-proxy service did not come up (docker compose logs btc-proxy)"
      sleep 2
    done
    gen_host=btc-proxy; gen_port=$PROXY_PORT; gen_user=localnet; gen_pass=localnet
    node_host=btc-proxy
    rpc_url="http://127.0.0.1:$PROXY_PORT"
    rpc_auth=""
    network=(--network qbtc-localnet)
  fi

  local tip init enable=2
  tip=$(btc_rpc "$rpc_url" "$rpc_auth" getblockcount) || die "cannot read the Bitcoin tip from $rpc_url"
  init=${BTC_INITIAL_HEIGHT:-$((tip - DEPTH))}
  if [ -n "${GENESIS_BIN:-}" ]; then
    [ -f "$GENESIS_BIN" ] || die "GENESIS_BIN $GENESIS_BIN not found"
    [ -n "${BTC_INITIAL_HEIGHT:-}" ] || die "BTC_INITIAL_HEIGHT is required with GENESIS_BIN: the height after the snapshot's"
    # the snapshot loads one chunk of 1,000,000 UTXOs per block from height 1,
    # and Bitcoin ingestion must not start before the last chunk: every record
    # is over 128 bytes, so this bounds the number of chunks
    local size chunks
    size=$(wc -c < "$GENESIS_BIN")
    chunks=$(( (size + 128000000 - 1) / 128000000 ))
    enable=$((chunks + 1))
    log "snapshot $GENESIS_BIN: at most $chunks chunks, vote extensions from height $enable"
  fi
  log "Bitcoin tip $tip; the chain starts at $init (chain ID $CHAIN_ID)"

  docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp "${network[@]}" \
    --add-host host.docker.internal:host-gateway -v "$NET:/net" "$IMAGE" \
    qbtcd multi-node --v 4 --output-dir /net --chain-id "$CHAIN_ID" \
    --btc-initial-height "$init" --vote-extensions-enable-height "$enable" \
    --bitcoin-rpc-host "$gen_host" --bitcoin-rpc-port "$gen_port" \
    --bitcoin-rpc-user "$gen_user" --bitcoin-rpc-password "$gen_pass" \
    --node-bitcoin-rpc-host "$node_host" --node-bitcoin-rpc-port "$gen_port" \
    --confirmation-depth "$DEPTH" --enable-api --docker-image "$IMAGE" \
    || die "network generation failed"

  if [ -n "${GENESIS_UTXO:-}" ]; then
    local specs vk
    read -ra specs <<< "${GENESIS_UTXO//,/ }"
    vk=${ZK_VERIFYING_KEY:-$ROOT/tests/vetest/.cache/zk/setup/verifying.key}
    [ -f "$vk" ] || die "ZK verifying key $vk not found (tests/vetest/run.sh builds it for S9; or set ZK_VERIFYING_KEY)"
    python3 "$VETEST_LIB" genesis-utxos --out "$NET/genesis_utxos.json" "${specs[@]}" >/dev/null
    python3 "$VETEST_LIB" genesis-patch --net "$NET" --utxo-file "$NET/genesis_utxos.json" --vk-file "$vk" >/dev/null
    log "genesis: ${#specs[@]} UTXO(s) with the ZK verifying key $vk"
  fi

  if [ -n "${GENESIS_BIN:-}" ]; then
    # each node splits its copy into chunks and deletes it, so the snapshot
    # must be a regular file in every config directory: a hard link when the
    # file system allows it, a copy otherwise
    local i
    for i in 0 1 2 3; do
      ln "$GENESIS_BIN" "$NET/validator$i/config/genesis.bin" 2>/dev/null ||
        cp "$GENESIS_BIN" "$NET/validator$i/config/genesis.bin"
    done
  fi
}

up() {
  command -v docker >/dev/null || die "docker is required"
  docker compose version >/dev/null 2>&1 || die "docker compose (v2) is required"
  if [ -n "${GENESIS_UTXO:-}" ]; then        # validate before anything is started
    local specs
    read -ra specs <<< "${GENESIS_UTXO//,/ }"
    python3 "$VETEST_LIB" genesis-utxos --out /dev/null "${specs[@]}" >/dev/null || exit 2
  fi
  ensure_image
  if [ -d "$NET/validator0" ]; then
    log "using the network in $NET (make localnet-clean to generate a new one)"
  else
    generate
  fi
  record_ports
  compose up -d
  local i rpc=() api=() grpc=()
  for i in 0 1 2 3; do
    rpc+=("$(host_port RPC "$i")"); api+=("$(host_port API "$i")"); grpc+=("$(host_port GRPC "$i")")
  done
  echo
  echo "4 validators up. Validator i: CometBFT RPC ${rpc[*]}, REST ${api[*]}, gRPC ${grpc[*]}"
  echo "  curl localhost:${api[0]}/qbtc/v1/last_processed_block"
  echo "  docker compose -p qbtc-localnet logs -f node_0"
  echo "  make localnet-status | localnet-down | localnet-clean"
}

status() {
  local i h lpb
  load_ports
  for i in 0 1 2 3; do
    h=$(curl -sf --max-time 3 "http://127.0.0.1:$(host_port RPC "$i")/status" 2>/dev/null |
      python3 -c 'import json, sys; print(json.load(sys.stdin)["result"]["sync_info"]["latest_block_height"])' 2>/dev/null || echo "-")
    lpb=$(curl -sf --max-time 3 "http://127.0.0.1:$(host_port API "$i")/qbtc/v1/last_processed_block" 2>/dev/null |
      python3 -c 'import json, sys; print(json.load(sys.stdin)["height"])' 2>/dev/null || echo "-")
    echo "validator $i: height $h, last processed Bitcoin block $lpb"
  done
  if [ -f "$ENV_FILE" ] && grep -q '^COMPOSE_PROFILES=proxy$' "$ENV_FILE"; then
    echo "btc-proxy: $(curl -sf --max-time 3 "http://127.0.0.1:$PROXY_CONTROL/tip" 2>/dev/null || echo down)"
  fi
}

case "${1:-}" in
  up) up ;;
  status) status ;;
  down) compose down ;;
  clean)
    compose down -v 2>/dev/null || true
    rm -rf "$NET"
    log "removed $NET"
    ;;
  *)
    sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
