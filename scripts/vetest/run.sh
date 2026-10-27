#!/usr/bin/env bash
# End-to-end scenario harness for Bitcoin ingestion through ABCI vote
# extensions: 4 qbtc validators in Docker, each reading Bitcoin MAINNET through a
# fault-injecting proxy. See scripts/vetest/README.md.
#
#   scripts/vetest/run.sh                  # everything, tear down at the end
#   scripts/vetest/run.sh --only S3,S9     # selected scenarios
#   scripts/vetest/run.sh --keep           # leave the network running
#   scripts/vetest/run.sh --clean          # only remove containers/network/output
#   scripts/vetest/run.sh --follow-mainnet # implies --keep; then keeps ingesting new mainnet blocks
#   scripts/vetest/run.sh --keep --genesis-utxo TXID:VOUT:SATS:ADDR   # then claim it with claim.sh
#
# Target: a Linux server (bash, GNU coreutils, docker compose v2, python3, Go 1.26.x).
# Run scripts/vetest/preflight.sh (or `run.sh --check`) first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="$SCRIPT_DIR/out"
CACHE="$SCRIPT_DIR/.cache"
LIB="$SCRIPT_DIR/vetest_lib.py"

# ----------------------------------------------------------------- settings
PROJECT=${VETEST_PROJECT:-vetest}
NETWORK=${VETEST_NETWORK:-vetest-net}
CHAIN_ID=${VETEST_CHAIN_ID:-qbtc-vetest}
IMG_NORMAL=${IMG_NORMAL:-qbtcd-vetest:normal}
IMG_MAL=${IMG_MAL:-qbtcd-vetest:malicious}
VENDOR=0                                       # --vendor: build from a host-vendored context

UPSTREAM=${UPSTREAM:-esplora:https://mempool.space/api}
PROXY_IMAGE=${PROXY_IMAGE:-python:3.12-alpine}
PROXY_CONTAINER=${PROXY_CONTAINER:-vetest-btc-proxy}
BTC_BASE_PORT=${BTC_BASE_PORT:-18440}          # validator i reads Bitcoin from BASE+i
BTC_TOOL_PORT=${BTC_TOOL_PORT:-18449}          # generator / tools
BTC_CONTROL_PORT=${BTC_CONTROL_PORT:-18450}    # fault injection, /truth
CONTROL="http://127.0.0.1:$BTC_CONTROL_PORT"
TSS_PORT=${TSS_PORT:-18480}

ENABLE_HEIGHT=${ENABLE_HEIGHT:-10}             # consensus vote_extensions_enable_height
DEPTH=${CONFIRMATION_DEPTH:-6}                 # [ebifrost] confirmation_depth
POLL_INTERVAL=${POLL_INTERVAL:-2s}             # [ebifrost] poll_interval
BACKLOG=${BACKLOG:-150}                        # confirmed blocks to ingest right after activation
EXTRA_BLOCKS=${EXTRA_BLOCKS:-130}              # prefetched blocks the scenarios release in batches
BATCH=${BATCH:-14}                             # blocks released per scenario phase
INITIAL_HEIGHT=${BTC_INITIAL_HEIGHT:-}         # default: derived from the mainnet tip
PREFETCH_TIMEOUT=${PREFETCH_TIMEOUT:-3600}

NET="$OUT/net"
CTX="$OUT/ctx"
LOGS="$OUT/logs"
RESULTS_TSV="$OUT/results.tsv"

KEEP=0
FOLLOW=0
GENESIS_UTXOS=()
ONLY=""
NO_BUILD=0
CLEAN_ONLY=0

usage() {
  sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  --keep             leave the network, proxy and output in place
  --follow-mainnet   implies --keep; after the scenarios lift the proxy release cap so the
                     chain keeps ingesting new mainnet blocks (for claim.sh with fresh UTXOs)
  --genesis-utxo TXID:VOUT:AMOUNT_SATS:ADDRESS
                     add a UTXO (P2PKH or P2WPKH mainnet address) to genesis next to the S9
                     test UTXO; repeatable; claim it later with claim.sh. Prepares the ZK material.
  --only S1,S3,...   run only these scenarios (S1..S9); S1 and S2 need a fresh network
  --check            run preflight.sh (tools, docker, reachability, disk) and exit
  --vendor           build the images from a host-vendored context (`go mod vendor`);
                     for hosts where the Docker build cannot download Go modules
  --no-build         reuse existing qbtcd-vetest:* images
  --backlog N        confirmed blocks to ingest at activation (default 150)
  --btc-initial-height H   fix the first Bitcoin height instead of deriving it from the tip
  --clean            remove containers, network and scripts/vetest/out, then exit
  -h, --help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1 ;;
    --follow-mainnet) KEEP=1; FOLLOW=1 ;;
    --genesis-utxo) GENESIS_UTXOS+=("${2:?--genesis-utxo needs TXID:VOUT:AMOUNT_SATS:ADDRESS}"); shift ;;
    --only) ONLY="${2:?--only needs a list}"; shift ;;
    --no-build) NO_BUILD=1 ;;
    --vendor) VENDOR=1 ;;
    --check) exec "$SCRIPT_DIR/preflight.sh" ;;
    --backlog) BACKLOG="${2:?}"; shift ;;
    --btc-initial-height) INITIAL_HEIGHT="${2:?}"; shift ;;
    --clean) CLEAN_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "${#GENESIS_UTXOS[@]}" -gt 0 ]; then       # validate before anything is started
  python3 "$LIB" genesis-utxos --out /dev/null "${GENESIS_UTXOS[@]}" >/dev/null || exit 2
fi

# --------------------------------------------------------------- utilities
mkdir -p "$OUT"
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT/run.log" >&2; }
die() { log "ERROR: $*"; exit 1; }
fail() { echo "ASSERT FAIL: $*" >&2; exit 1; }       # inside a scenario subshell: ends the scenario
detail() { echo "$*" >> "$OUT/$CUR_SCENARIO.detail"; echo "  - $*" >&2; }
selected() {
  [ -z "$ONLY" ] && return 0
  case ",$ONLY," in *",$1,"*) return 0 ;; esac
  return 1
}
need() { command -v "$1" >/dev/null 2>&1 || die "missing prerequisite: $1"; }
jget() { python3 "$LIB" jget "$@"; }

CUR_SCENARIO=setup
cname() { echo "${PROJECT}-node_$1-1"; }
rpc_port() { echo $((26657 - 3 * $1)); }
dc() { docker compose -p "$PROJECT" -f "$NET/docker-compose.yml" "$@"; }

# height of validator i according to its CometBFT RPC (published on the host); 0 when unreachable
chain_height() {
  curl -s --max-time 3 "http://127.0.0.1:$(rpc_port "$1")/status" 2>/dev/null \
    | jget - result.sync_info.latest_block_height 0 2>/dev/null || echo 0
}
# query helper: qq <node> <args...>
qq() {
  local i=$1; shift
  docker exec "$(cname "$i")" qbtcd q "$@" --node "tcp://localhost:$(rpc_port "$i")" -o json
}
# last processed Bitcoin height as seen by node (default 0), optionally at a qbtc height
lpb() {
  local i=${1:-0} h=${2:-}
  if [ -n "$h" ]; then
    qq "$i" qbtc last-processed-block --height "$h" 2>/dev/null | jget - height 0 2>/dev/null || echo 0
  else
    qq "$i" qbtc last-processed-block 2>/dev/null | jget - height 0 2>/dev/null || echo 0
  fi
}
wait_until() { # wait_until <timeout-s> <description> <condition...>
  local timeout=$1 desc=$2; shift 2
  local end=$((SECONDS + timeout))
  until eval "$*"; do
    [ "$SECONDS" -ge "$end" ] && fail "timeout after ${timeout}s waiting for: $desc"
    sleep 2
  done
}
proxy_post() { curl -sf -X POST --max-time 20 -d "$2" "$CONTROL$1" >/dev/null || die "proxy control $1 failed"; }
btc_mode() { # btc_mode <validator|all> <ok|down|fork|frozen> [from_height]
  proxy_post /mode "{\"validator\":\"$1\",\"mode\":\"$2\",\"from_height\":${3:-0}}"
  echo "  proxy: validator $1 -> $2 ${3:+(from $3)}" >&2
}
# hand out blocks: AVAIL confirmed blocks starting at INIT are visible to the validators
# (kept in a file: scenarios run in subshells)
release_to() {
  echo "$1" > "$OUT/avail"
  proxy_post /release "{\"height\":$((INIT + $1 + DEPTH - 2))}"
}
release_more() {
  local n=$(( $(cat "$OUT/avail") + $1 ))
  release_to "$n"
  echo "  proxy: $n blocks released so far (served tip $((INIT + n + DEPTH - 2)))" >&2
}
truth_hash() { curl -sf --max-time 30 "$CONTROL/truth/$1"; }

strip_ansi() { sed -E 's/\x1b\[[0-9;?]*[ -\/]*[@-~]//g'; }
# snap_logs <tag> [since-epoch]: node logs since the epoch (all when omitted), ANSI stripped
snap_logs() {
  local tag=$1 since=${2:-} d="$LOGS/$1" i args
  mkdir -p "$d"
  for i in 0 1 2 3; do
    args=""
    [ -n "$since" ] && args="--since $(( $(date +%s) - since + 3 ))s"
    # shellcheck disable=SC2086
    docker logs $args "$(cname "$i")" 2>&1 | strip_ansi > "$d/node_$i.log" || true
  done
  echo "$d"
}
count_in_logs() { # count_in_logs <pattern> <since-epoch> <nodes...>
  local pat=$1 since=$2 n total=0 c; shift 2
  for n in "$@"; do
    c=$(docker logs --since "$(( $(date +%s) - since + 3 ))s" "$(cname "$n")" 2>&1 | grep -c "$pat" || true)
    total=$((total + c))
  done
  echo "$total"
}
wait_caught_up() { # wait_caught_up <node>
  local ref=0
  [ "$1" = 0 ] && ref=1
  wait_until 180 "node $1 to catch up with node $ref" '[ "$(chain_height '"$1"')" -gt 0 ] && [ "$(chain_height '"$1"')" -ge $(( $(chain_height '"$ref"') - 2 )) ]'
}
wait_height_gt() { # wait_height_gt <node> <height> <timeout>
  wait_until "${3:-120}" "node $1 height > $2" '[ "$(chain_height '"$1"')" -gt '"$2"' ]'
}

# ------------------------------------------------------------------- cleanup
stop_host_procs() {
  local f p
  for f in "$OUT/proxy.pid" "$OUT/tss.pid"; do
    if [ -f "$f" ]; then
      p=$(cat "$f"); kill "$p" 2>/dev/null || true; rm -f "$f"
    fi
  done
}
teardown() {
  log "tearing down containers and network"
  if [ -f "$NET/docker-compose.yml" ]; then dc down -v --remove-orphans >/dev/null 2>&1 || true; fi
  docker rm -f "$PROXY_CONTAINER" >/dev/null 2>&1 || true
  stop_host_procs
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
cleanup_previous() {
  if [ -f "$NET/docker-compose.yml" ]; then dc down -v --remove-orphans >/dev/null 2>&1 || true; fi
  docker rm -f "$PROXY_CONTAINER" >/dev/null 2>&1 || true
  stop_host_procs
  rm -rf "$NET" 2>/dev/null || docker run --rm -v "$OUT:/o" alpine:3.23 rm -rf /o/net
  rm -rf "$CTX" "$LOGS" "$RESULTS_TSV" "$OUT/results.json" "$OUT"/*.detail "$OUT"/S*.log "$OUT/claim" "$OUT/avail" "$OUT/network.env"
}

if [ "$CLEAN_ONLY" = 1 ]; then
  need docker
  teardown
  rm -rf "$OUT"
  echo "cleaned"
  exit 0
fi

# ------------------------------------------------------------- prerequisites
need docker; need go; need python3; need git; need curl; need sed; need tar
if selected S9 || [ "${#GENESIS_UTXOS[@]}" -gt 0 ]; then WANT_ZK=1; else WANT_ZK=0; fi
if [ "$WANT_ZK" = 1 ]; then need openssl; fi
docker info >/dev/null 2>&1 || die "the Docker daemon is not running"
: > "$OUT/run.log"
cleanup_previous
mkdir -p "$LOGS" "$CACHE/btc" "$CACHE/bin" "$CACHE/zk"
: > "$RESULTS_TSV"
trap 'rc=$?; if [ "$KEEP" = 1 ]; then log "--keep: network left running (project $PROJECT, output $OUT)"; else teardown; fi; exit $rc' EXIT

if selected S8; then WANT_MAL=1; else WANT_MAL=0; fi

# ------------------------------------------------------------------ step 1: proxy
docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK" >/dev/null

start_proxy() {
  NODE_BTC_HOST=btc-proxy
  GEN_BTC_HOST=btc-proxy
  docker run -d --name "$PROXY_CONTAINER" --network "$NETWORK" --network-alias btc-proxy \
    -p "127.0.0.1:$BTC_TOOL_PORT:$BTC_TOOL_PORT" -p "127.0.0.1:$BTC_CONTROL_PORT:$BTC_CONTROL_PORT" \
    -v "$SCRIPT_DIR/btc_proxy.py:/app/btc_proxy.py:ro" -v "$CACHE/btc:/cache" \
    -e UPSTREAM="$UPSTREAM" -e CACHE_DIR=/cache -e BIND=0.0.0.0 -e BASE_PORT="$BTC_BASE_PORT" \
    -e TOOL_PORT="$BTC_TOOL_PORT" -e CONTROL_PORT="$BTC_CONTROL_PORT" -e NUM_VALIDATORS=4 \
    "$PROXY_IMAGE" python -u /app/btc_proxy.py >/dev/null
  local end=$((SECONDS + 90))
  until curl -sf --max-time 3 "$CONTROL/tip" >/dev/null 2>&1; do
    [ "$SECONDS" -ge "$end" ] && die "bitcoin proxy did not come up (see docker logs $PROXY_CONTAINER)"
    sleep 1
  done
}
CUR_SCENARIO=setup
log "starting the bitcoin proxy container (upstream $UPSTREAM)"
start_proxy
REAL_TIP=$(curl -sf "$CONTROL/tip" | jget - real_tip)
if [ -z "$INITIAL_HEIGHT" ]; then
  INIT=$((REAL_TIP - (BACKLOG + EXTRA_BLOCKS + DEPTH) + 1))
else
  INIT=$INITIAL_HEIGHT
fi
LAST_PREFETCH=$((INIT + BACKLOG + EXTRA_BLOCKS - 1))
[ "$LAST_PREFETCH" -le "$((REAL_TIP - DEPTH + 1))" ] || die "btc range $INIT..$LAST_PREFETCH is above the confirmed tip $REAL_TIP"
log "mainnet tip $REAL_TIP; chain starts at btc height $INIT ($BACKLOG backlog + $EXTRA_BLOCKS released later)"
# nothing visible yet except the anchor; blocks are handed out with release_to
release_to 0
proxy_post /prefetch "{\"from\":$((INIT - 1)),\"to\":$LAST_PREFETCH}"
log "prefetching mainnet blocks $((INIT - 1))..$LAST_PREFETCH into $CACHE/btc (background)"

# -------------------------------------------------------- step 2: images
build_context() {
  log "assembling the vendored build context"
  rm -rf "$CTX"; mkdir -p "$CTX"
  (cd "$ROOT" && git ls-files -z -c -o --exclude-standard) | python3 -c '
import os, sys
root = sys.argv[1]
names = sys.stdin.buffer.read().split(b"\0")
skip = (b".claude/", b"scripts/vetest/", b".git/", b"vendor/")
out = [n for n in names if n and not n.startswith(skip) and os.path.lexists(os.path.join(root.encode(), n))]
sys.stdout.buffer.write(b"\0".join(out) + b"\0")
' "$ROOT" > "$OUT/ctx.files"
  tar -C "$ROOT" --null -T "$OUT/ctx.files" -cf - | tar -C "$CTX" -xf -
  if [ "$VENDOR" = 1 ]; then
    log "running go mod vendor in the build context"
    (cd "$CTX" && go mod vendor) || die "go mod vendor failed"
  fi
}
build_images() {
  if [ "$NO_BUILD" = 1 ] && docker image inspect "$IMG_NORMAL" >/dev/null 2>&1 \
     && { [ "$WANT_MAL" = 0 ] || docker image inspect "$IMG_MAL" >/dev/null 2>&1; }; then
    log "reusing existing images"
    return
  fi
  build_context
  log "building $IMG_NORMAL (a few minutes on the first run)"
  docker build -f "$SCRIPT_DIR/Dockerfile" --build-arg VENDOR="$VENDOR" -t "$IMG_NORMAL" "$CTX" > "$OUT/build_normal.log" 2>&1 \
    || { tail -30 "$OUT/build_normal.log" >&2; die "image build failed (see $OUT/build_normal.log)"; }
  if [ "$WANT_MAL" = 1 ]; then
    log "building $IMG_MAL (-tags vetest_malicious)"
    docker build -f "$SCRIPT_DIR/Dockerfile" --build-arg VENDOR="$VENDOR" --build-arg EXTRA_TAGS=vetest_malicious -t "$IMG_MAL" "$CTX" > "$OUT/build_malicious.log" 2>&1 \
      || { tail -30 "$OUT/build_malicious.log" >&2; die "malicious image build failed (see $OUT/build_malicious.log)"; }
  fi
  rm -rf "$CTX"
}
build_images

# ------------------------------------------------------ step 3: ZK material
prep_zk() {
  log "S9 preparation: ZK setup (cached), test key, genesis UTXO"
  (cd "$ROOT" && go build -o "$CACHE/bin/zkprover" ./cmd/zkprover && go build -o "$CACHE/bin/tss-emulator" ./cmd/tss-emulator) \
    || die "building zkprover/tss-emulator failed"
  if [ ! -f "$CACHE/zk/setup/verifying.key" ] || [ ! -f "$CACHE/zk/setup/proving.key" ] || [ ! -f "$CACHE/zk/setup/circuit.cs" ]; then
    log "running the PLONK trusted setup (downloads the 2.4 GB Hermez ptau on the first run; cached in $CACHE/zk)"
    "$CACHE/bin/zkprover" setup --output "$CACHE/zk/setup" --cache-dir "$CACHE/zk" > "$OUT/zk_setup.log" 2>&1 \
      || die "zkprover setup failed, see $OUT/zk_setup.log"
  fi
  mkdir -p "$OUT/claim"
  openssl rand -hex 32 > "$OUT/claim/btc_key.hex"
  chmod 600 "$OUT/claim/btc_key.hex"
  # the key goes in through the environment (TSS_PRIVATE_KEY), not argv, so it is not visible in ps
  TSS_PRIVATE_KEY="$(cat "$OUT/claim/btc_key.hex")" "$CACHE/bin/tss-emulator" --port "127.0.0.1:$TSS_PORT" > "$OUT/tss.log" 2>&1 &
  echo $! > "$OUT/tss.pid"
  local end=$((SECONDS + 20))
  until curl -sf "http://127.0.0.1:$TSS_PORT/info" > "$OUT/claim/info.json" 2>/dev/null; do
    [ "$SECONDS" -ge "$end" ] && die "tss-emulator did not start"
    sleep 1
  done
  CLAIM_HASH160=$(jget "$OUT/claim/info.json" address_hash)
  CLAIM_BTC_ADDR=$(python3 "$LIB" bech32-p2wpkh "$CLAIM_HASH160")
  CLAIM_TXID=$(openssl rand -hex 32)
  CLAIM_AMOUNT=${CLAIM_AMOUNT:-123456789}
  cat > "$OUT/claim/utxos.json" <<EOF
[{"txid": "$CLAIM_TXID", "vout": 0, "amount": "$((CLAIM_AMOUNT * 2))", "entitled_amount": "$CLAIM_AMOUNT",
  "script_pub_key": {"hex": "0014$CLAIM_HASH160", "type": "witness_v0_keyhash", "address": "$CLAIM_BTC_ADDR"},
  "block_height": "0"}]
EOF
  log "claim fixture: $CLAIM_BTC_ADDR (hash160 $CLAIM_HASH160), utxo $CLAIM_TXID:0 entitled $CLAIM_AMOUNT"
  if [ "${#GENESIS_UTXOS[@]}" -gt 0 ]; then
    python3 "$LIB" genesis-utxos --base "$OUT/claim/utxos.json" --out "$OUT/claim/utxos.merged.json" "${GENESIS_UTXOS[@]}" >/dev/null 2>&1 \
      || die "could not build the genesis UTXO list"
    mv "$OUT/claim/utxos.merged.json" "$OUT/claim/utxos.json"
    log "genesis gets ${#GENESIS_UTXOS[@]} extra UTXO(s) to claim with claim.sh"
  fi
}
if [ "$WANT_ZK" = 1 ]; then prep_zk; fi

# ------------------------------------------------------ step 4: generate network
log "generating the 4-validator network (anchor read from the proxy tool port)"
mkdir -p "$NET"
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp --network "$NETWORK" \
  -v "$NET:/net" "$IMG_NORMAL" \
  qbtcd multi-node --v 4 --output-dir /net --chain-id "$CHAIN_ID" \
    --btc-initial-height "$INIT" \
    --bitcoin-rpc-host "$GEN_BTC_HOST" --bitcoin-rpc-port "$BTC_TOOL_PORT" \
    --bitcoin-rpc-user vetest --bitcoin-rpc-password vetest \
    --node-bitcoin-rpc-host "$NODE_BTC_HOST" --node-bitcoin-rpc-port "$BTC_BASE_PORT" --node-bitcoin-rpc-port-step 1 \
    --confirmation-depth "$DEPTH" --poll-interval "$POLL_INTERVAL" \
    --vote-extensions-enable-height "$ENABLE_HEIGHT" \
    --docker-image "$IMG_NORMAL" --docker-network "$NETWORK" > "$OUT/generate.log" 2>&1 \
  || { tail -20 "$OUT/generate.log" >&2; die "network generation failed (see $OUT/generate.log)"; }

PATCH_ARGS="--net $NET --enable-height $ENABLE_HEIGHT"
if [ "$WANT_ZK" = 1 ]; then
  PATCH_ARGS="$PATCH_ARGS --utxo-file $OUT/claim/utxos.json --vk-file $CACHE/zk/setup/verifying.key"
fi
# shellcheck disable=SC2086
python3 "$LIB" genesis-patch $PATCH_ARGS >/dev/null

# -------------------------------------------------- step 5: wait for prefetch, start
log "waiting for the block prefetch"
end=$((SECONDS + PREFETCH_TIMEOUT)); last_report=0
while :; do
  st=$(curl -sf "$CONTROL/prefetch" || echo '{}')
  running=$(echo "$st" | jget - running True); done_n=$(echo "$st" | jget - done 0); failed=$(echo "$st" | jget - failed 0)
  total=$(echo "$st" | jget - total 0)
  [ "$running" = False ] && break
  if [ $((SECONDS - last_report)) -ge 20 ]; then log "  prefetch $done_n/$total (failed $failed)"; last_report=$SECONDS; fi
  [ "$SECONDS" -ge "$end" ] && die "prefetch timed out"
  sleep 3
done
[ "$failed" = 0 ] || die "prefetch failed for $failed blocks (upstream trouble; see docker logs $PROXY_CONTAINER)"
log "prefetched $done_n blocks"

# hand out the backlog before the chain starts, so the readers have it cached when
# vote extensions switch on at height $ENABLE_HEIGHT
release_to "$BACKLOG"
log "starting the validators (vote extensions enabled from height $ENABLE_HEIGHT)"
dc up -d >/dev/null 2>&1 || die "docker compose up failed"
end=$((SECONDS + 180))
for i in 0 1 2 3; do
  until [ "$(chain_height $i)" -ge 1 ]; do
    [ "$SECONDS" -ge "$end" ] && { dc logs --tail 30 >&2 || true; die "validator $i did not produce blocks"; }
    sleep 2
  done
done
log "chain is up (height $(chain_height 0))"

# settings for claim.sh (sourced by it); written once the network is up
{
  for v in PROJECT NETWORK CHAIN_ID SCRIPT_DIR OUT CACHE NET TSS_PORT BTC_CONTROL_PORT INIT DEPTH FOLLOW; do
    printf '%s=%q\n' "VETEST_$v" "${!v}"
  done
} > "$OUT/network.env"

# ---------------------------------------------------------------- scenarios
INDEXED_LAST=$((INIT - 1 + BACKLOG))
backlog_drained() { [ "$(lpb 0)" -ge "$INDEXED_LAST" ]; }

record() { # record <name> <PASS|FAIL|SKIP> <seconds> <detail>
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RESULTS_TSV"
}
run_scenario() { # run_scenario <name> <function>
  local name=$1 fn=$2 t0 rc status det
  if ! selected "$name"; then return 0; fi
  CUR_SCENARIO=$name
  : > "$OUT/$name.detail"
  log "=== $name: $(echo "$fn" | tr '_' ' ') ==="
  t0=$SECONDS
  set +e
  ( set -e; "$fn" ) > "$OUT/$name.log" 2>&1
  rc=$?
  set -e
  cat "$OUT/$name.log" >> "$OUT/run.log"
  det=$(tr '\n' ';' < "$OUT/$name.detail" | sed 's/;$//')
  if [ "$rc" = 0 ]; then
    status=PASS
  elif [ "$rc" = 77 ]; then
    status=SKIP
    det=$(grep -m1 '^SKIP:' "$OUT/$name.log" | sed 's/^SKIP: //' || true)
  else
    status=FAIL
    det="$(grep -m1 'ASSERT FAIL' "$OUT/$name.log" | sed 's/^ASSERT FAIL: //' || true)${det:+ | $det}"
    [ -n "$det" ] || det="exit code $rc (see $OUT/$name.log)"
  fi
  record "$name" "$status" "$((SECONDS - t0))" "$det"
  log "$name: $status ($((SECONDS - t0))s)"
  CUR_SCENARIO=setup
}
skip() { echo "SKIP: $*" >&2; exit 77; }

ensure_drained() {
  if ! backlog_drained; then
    log "waiting for the initial backlog to be ingested"
    local end=$((SECONDS + 900))
    until backlog_drained; do
      [ "$SECONDS" -ge "$end" ] && fail "backlog was not ingested within 900 s (lpb $(lpb 0), wanted $INDEXED_LAST)"
      sleep 3
    done
  fi
}

# --- S1: activation ----------------------------------------------------------
s1_activation() {
  wait_until 300 "the first Bitcoin block to be processed" '[ "$(lpb 0)" -ge '"$INIT"' ]'
  local first="" h v
  # state after each qbtc block: the last processed Bitcoin height (anchor = INIT-1 until the first injection)
  for h in $(seq $((ENABLE_HEIGHT - 2)) $((ENABLE_HEIGHT + 8))); do
    wait_height_gt 0 "$h" 120
    v=0
    for _try in 1 2 3; do
      v=$(lpb 0 "$h")
      [ "$v" != 0 ] && break
      sleep 2
    done
    echo "  height $h: last processed btc $v" >&2
    if [ "$v" -ge "$INIT" ] && [ -z "$first" ]; then first=$h; fi
    if [ "$h" -le "$ENABLE_HEIGHT" ] && [ "$v" -ne $((INIT - 1)) ]; then
      fail "a Bitcoin block was processed by height $h, before vote extensions are active (enable height $ENABLE_HEIGHT)"
    fi
  done
  [ -n "$first" ] || fail "no Bitcoin block processed within 8 blocks of the enable height"
  [ "$first" -ge $((ENABLE_HEIGHT + 1)) ] || fail "first injection at height $first, expected >= $((ENABLE_HEIGHT + 1))"
  detail "enable height $ENABLE_HEIGHT; first injection at qbtc height $first; none before"
  local d; d=$(snap_logs S1)
  local n; n=$(grep -h -c "btc block processed" "$d"/node_*.log | awk '{s += $1} END {print s + 0}')
  [ "$n" -gt 0 ] || fail "no 'btc block processed' lines in the node logs"
  detail "'btc block processed' lines across nodes: $n"
}

# --- S2: happy path ----------------------------------------------------------
s2_happy_path() {
  ensure_drained
  local d; d=$(snap_logs S2)
  python3 "$LIB" processed --logs "$d" --truth "$CONTROL" --min-count "$BACKLOG" --consecutive
  python3 "$LIB" tallies --logs "$d" --truth "$CONTROL" --power-eq 1 --min-run 10
  detail "applied hashes equal mainnet; >= 10 consecutive heights tallied with power == total"
  local h; h=$(chain_height 0)
  local bt; bt=$(python3 "$LIB" blocktime --rpc "http://127.0.0.1:$(rpc_port 0)" --from $((h - 20)) --to "$h")
  detail "qbtc block time ${bt}s (last 20 blocks)"
  python3 "$LIB" sizes --logs "$d" | tee "$OUT/S2.sizes" >&2
  detail "sizes: $(tr -s ' ' < "$OUT/S2.sizes" | paste -sd'|' -)"
}

# --- S3: one validator's Bitcoin is down ----------------------------------------
s3_one_btc_down() {
  ensure_drained
  local t0 L0 d L1 t1
  t0=$(date +%s); L0=$(lpb 0)
  btc_mode 3 down
  release_more "$BATCH"
  wait_until 300 "ingestion with validator 3 offline" '[ "$(lpb 0)" -ge '"$((L0 + 10))"' ]'
  d=$(snap_logs S3_down "$t0")
  python3 "$LIB" tallies --logs "$d" --after "$L0" --truth "$CONTROL" --power-eq 3/4 --strict --min-count 8
  python3 "$LIB" processed --logs "$d" --after "$L0" --truth "$CONTROL" --min-count 8
  detail "with validator 3's Bitcoin down: >= 8 heights ingested at power 3/4 of total"
  btc_mode 3 ok
  t1=$(date +%s); L1=$(lpb 0)
  release_more "$BATCH"
  wait_until 300 "ingestion after restoring validator 3" '[ "$(lpb 0)" -ge '"$((L1 + 10))"' ]'
  d=$(snap_logs S3_restored "$t1")
  python3 "$LIB" tallies --logs "$d" --after "$L1" --last 4 --truth "$CONTROL" --power-eq 1 --strict --min-count 4
  detail "after restoring: votes back to 4/4"
}

# --- S4: one validator on a fork -----------------------------------------------
s4_one_fork() {
  ensure_drained
  local t0 L0 d L1 t1
  t0=$(date +%s); L0=$(lpb 0)
  btc_mode 3 fork $((L0 + 1))
  release_more "$BATCH"
  wait_until 300 "ingestion with validator 3 on a fork" '[ "$(lpb 0)" -ge '"$((L0 + 10))"' ]'
  d=$(snap_logs S4_fork "$t0")
  python3 "$LIB" tallies --logs "$d" --after "$L0" --truth "$CONTROL" --two-candidates --min-count 6
  python3 "$LIB" processed --logs "$d" --after "$L0" --truth "$CONTROL" --min-count 8
  detail ">= 6 tallies with two candidates (3/4 mainnet vs 1/4 fork); applied hashes equal mainnet"
  btc_mode 3 ok
  t1=$(date +%s); L1=$(lpb 0)
  release_more "$BATCH"
  wait_until 300 "ingestion after the fork is repaired" '[ "$(lpb 0)" -ge '"$((L1 + 10))"' ]'
  d=$(snap_logs S4_restored "$t1")
  python3 "$LIB" tallies --logs "$d" --after "$L1" --last 4 --truth "$CONTROL" --power-eq 1 --strict --min-count 4
  detail "after restoring: votes back to 4/4"
}

# --- S5: three validators lose Bitcoin ------------------------------------------
s5_three_btc_down() {
  ensure_drained
  local L0 h0 h1 L1 t_restore
  L0=$(lpb 0); h0=$(chain_height 0)
  btc_mode 1 down; btc_mode 2 down; btc_mode 3 down
  release_more "$BATCH"
  wait_until 180 "consensus to advance 5 heights" '[ "$(chain_height 0)" -ge '"$((h0 + 5))"' ]'
  sleep 20
  h1=$(chain_height 0); L1=$(lpb 0)
  [ "$h1" -ge $((h0 + 5)) ] || fail "consensus height advanced only $((h1 - h0)) (< 5)"
  [ "$L1" -eq "$L0" ] || fail "last processed Bitcoin height moved from $L0 to $L1 although only 1 of 4 validators sees Bitcoin"
  detail "consensus advanced $((h1 - h0)) heights while the last processed btc height stayed at $L0"
  btc_mode all ok
  t_restore=$SECONDS
  wait_until 240 "ingestion to resume" '[ "$(lpb 0)" -ge '"$((L0 + 8))"' ]'
  detail "ingestion resumed $((SECONDS - t_restore))s after restoring (8 blocks ingested)"
}

# --- S6: one validator offline (docker stop) ------------------------------------
s6_one_node_offline() {
  ensure_drained
  local t0 L0 d L1 t1
  t0=$(date +%s); L0=$(lpb 0)
  docker stop "$(cname 3)" >/dev/null
  release_more "$BATCH"
  wait_until 300 "ingestion with validator 3 stopped" '[ "$(lpb 0)" -ge '"$((L0 + 10))"' ]'
  d=$(snap_logs S6_offline "$t0")
  python3 "$LIB" tallies --logs "$d" --after "$L0" --truth "$CONTROL" --power-eq 3/4 --strict --min-count 8
  detail "consensus and ingestion continued with validator 3 stopped (power 3/4)"
  t1=$(date +%s)
  docker start "$(cname 3)" >/dev/null
  wait_caught_up 3
  L1=$(lpb 0)
  release_more "$BATCH"
  wait_until 300 "ingestion after validator 3 restarted" '[ "$(lpb 0)" -ge '"$((L1 + 10))"' ]'
  d=$(snap_logs S6_restarted "$t1")
  python3 "$LIB" tallies --logs "$d" --after "$L1" --last 4 --truth "$CONTROL" --power-eq 1 --strict --min-count 4
  local cached; cached=$(grep -c "btc block cached" "$d/node_3.log" || true)
  [ "$cached" -gt 0 ] || fail "restarted validator 3 logged no 'btc block cached' (cache was not refilled)"
  detail "validator 3 caught up, refilled its cache ($cached blocks) and its votes returned (4/4)"
}

# --- S7: two validators offline ----------------------------------------------------
s7_two_nodes_offline() {
  ensure_drained
  local L0 ha hb
  L0=$(lpb 0)
  docker stop "$(cname 2)" "$(cname 3)" >/dev/null
  sleep 15
  ha=$(chain_height 0)
  sleep 35
  hb=$(chain_height 0)
  [ "$ha" = "$hb" ] || fail "chain advanced from $ha to $hb with half of the voting power offline (halt expected)"
  detail "chain halted at height $hb for >= 35 s (2 of 4 validators = 50% < 2/3)"
  docker start "$(cname 2)" "$(cname 3)" >/dev/null
  wait_until 240 "the chain to recover" '[ "$(chain_height 0)" -ge '"$((hb + 3))"' ]'
  wait_caught_up 2; wait_caught_up 3
  release_more "$BATCH"
  wait_until 300 "ingestion after the recovery" '[ "$(lpb 0)" -ge '"$((L0 + 8))"' ]'
  detail "recovered; ingestion continued ($((L0 + 8)) reached)"
}

# --- S8: malicious proposer --------------------------------------------------------
mal_override() { # mal_override <mode>
  cat > "$NET/docker-compose.malicious.yml" <<EOF
services:
  node_0:
    image: $IMG_MAL
    environment:
      QBTC_VETEST_MALICIOUS: "$1"
EOF
}
s8_malicious_proposer() {
  ensure_drained
  local mode t0 L0 h0 rej d
  for mode in forge noevidence; do
    mal_override "$mode"
    docker compose -p "$PROJECT" -f "$NET/docker-compose.yml" -f "$NET/docker-compose.malicious.yml" \
      up -d --no-deps --force-recreate node_0 >/dev/null 2>&1 || fail "could not restart validator 0 on the malicious image"
    wait_caught_up 0
    t0=$(date +%s); L0=$(lpb 1); h0=$(chain_height 1)
    release_more "$BATCH"
    wait_until 300 "other validators to reject validator 0's '$mode' proposals" \
      '[ "$(count_in_logs "rejecting proposal" '"$t0"' 1 2 3)" -ge 1 ]'
    wait_until 300 "ingestion through the honest proposers ($mode)" '[ "$(lpb 1)" -ge '"$((L0 + 8))"' ]'
    d=$(snap_logs "S8_$mode" "$t0")
    python3 "$LIB" rejects --logs "$d" --nodes 1,2,3 --min 1
    python3 "$LIB" processed --logs "$d" --after "$L0" --truth "$CONTROL" --min-count 8
    [ "$(chain_height 1)" -ge $((h0 + 5)) ] || fail "chain stalled under the '$mode' proposer"
    rej=$(count_in_logs "rejecting proposal" "$t0" 1 2 3)
    detail "$mode: $rej rejections; chain kept committing; applied hashes equal mainnet"
  done
  # back to the honest image
  rm -f "$NET/docker-compose.malicious.yml"
  dc up -d --no-deps --force-recreate node_0 >/dev/null 2>&1 || fail "could not restore validator 0"
  wait_caught_up 0
  local t1 L1; t1=$(date +%s); L1=$(lpb 0)
  release_more "$BATCH"
  wait_until 300 "ingestion after restoring the honest image" '[ "$(lpb 0)" -ge '"$((L1 + 8))"' ]'
  d=$(snap_logs S8_restored "$t1")
  python3 "$LIB" tallies --logs "$d" --after "$L1" --last 4 --truth "$CONTROL" --power-eq 1 --strict --min-count 4
  detail "honest image restored: votes back to 4/4"
}

# --- S9: claim a genesis UTXO with a ZK proof ----------------------------------------
claim_tx() { # claim_tx -> prints the DeliverTx code (or CHECK:<code>) of one submission
  local out code hash end
  out=$(docker exec "$(cname 0)" qbtcd tx qbtc claim-with-proof /qbtc_data/.qbtc/claim_msg.json \
        --from validator0 --keyring-backend test --home /qbtc_data/.qbtc --chain-id "$CHAIN_ID" \
        --node "tcp://localhost:$(rpc_port 0)" --gas 2000000 --fees "0qbtc" -y --broadcast-mode sync -o json 2>&1 || true)
  echo "$out" > "$OUT/claim/tx_last.json"
  code=$(echo "$out" | jget - code "" 2>/dev/null || true)
  hash=$(echo "$out" | jget - txhash "" 2>/dev/null || true)
  if [ -z "$hash" ]; then echo "CHECK:error"; return 0; fi
  if [ -n "$code" ] && [ "$code" != 0 ]; then echo "CHECK:$code"; return 0; fi
  end=$((SECONDS + 90))
  while [ "$SECONDS" -lt "$end" ]; do
    if qq 0 tx "$hash" > "$OUT/claim/tx_result.json" 2>/dev/null; then
      jget "$OUT/claim/tx_result.json" code 0
      return 0
    fi
    sleep 2
  done
  echo "TIMEOUT"
}
s9_claim() {
  [ "$WANT_ZK" = 1 ] || fail "ZK material was not prepared"
  ensure_drained
  local dest claimer bal utxo_ent code1 code2 t_proof
  mkdir -p "$OUT/claim"
  docker exec "$(cname 0)" qbtcd keys add vetest-claim-dest --keyring-backend test --home /qbtc_data/.qbtc --output json \
    > "$OUT/claim/dest_key.json" 2>/dev/null || true
  dest=$(docker exec "$(cname 0)" qbtcd keys show vetest-claim-dest -a --keyring-backend test --home /qbtc_data/.qbtc)
  claimer=$(docker exec "$(cname 0)" qbtcd keys show validator0 -a --keyring-backend test --home /qbtc_data/.qbtc)
  [ -n "$dest" ] && [ -n "$claimer" ] || fail "could not create the claim destination key"
  bal=$(qq 0 bank balances "$dest" | jget - balances.0.amount 0)
  [ "$bal" = 0 ] || fail "fresh destination $dest unexpectedly holds $bal"
  utxo_ent=$(qq 0 qbtc utxo "$CLAIM_TXID" 0 | jget - utxo.entitled_amount 0)
  [ "$utxo_ent" = "$CLAIM_AMOUNT" ] || fail "genesis UTXO entitled amount is $utxo_ent, expected $CLAIM_AMOUNT"
  detail "destination $dest; genesis UTXO $CLAIM_TXID:0 entitled $CLAIM_AMOUNT"

  t_proof=$SECONDS
  "$CACHE/bin/zkprover" prove --tss-url "http://127.0.0.1:$TSS_PORT" --qbtc-address "$dest" --chain-id "$CHAIN_ID" \
    --address-hash "$CLAIM_HASH160" --setup-dir "$CACHE/zk/setup" -o "$OUT/claim/proof.json" > "$OUT/claim/prove.log" 2>&1 \
    || fail "zkprover prove failed, see $OUT/claim/prove.log"
  detail "PLONK proof generated in $((SECONDS - t_proof))s"
  python3 "$LIB" claim-msg --proof "$OUT/claim/proof.json" --claimer "$claimer" --receiver "$dest" \
    --txid "$CLAIM_TXID" --vout 0 --out "$NET/validator0/claim_msg.json"

  code1=$(claim_tx)
  [ "$code1" = 0 ] || fail "claim transaction failed: $code1 ($(head -c 400 "$OUT/claim/tx_last.json"))"
  bal=$(qq 0 bank balances "$dest" | jget - balances.0.amount 0)
  [ "$bal" = "$CLAIM_AMOUNT" ] || fail "destination balance is $bal, expected $CLAIM_AMOUNT"
  utxo_ent=$(qq 0 qbtc utxo "$CLAIM_TXID" 0 | jget - utxo.entitled_amount 0)
  [ "$utxo_ent" = 0 ] || fail "UTXO entitled amount is $utxo_ent after the claim, expected 0"
  detail "claim accepted: destination received $bal, UTXO entitled amount is now 0"

  code2=$(claim_tx)
  if [ "$code2" = 0 ]; then fail "a second identical claim was accepted"; fi
  bal=$(qq 0 bank balances "$dest" | jget - balances.0.amount 0)
  [ "$bal" = "$CLAIM_AMOUNT" ] || fail "balance changed to $bal after the replayed claim"
  detail "replayed claim rejected (code $code2), balance unchanged"
}

run_scenario S1 s1_activation
run_scenario S2 s2_happy_path
run_scenario S3 s3_one_btc_down
run_scenario S4 s4_one_fork
run_scenario S5 s5_three_btc_down
run_scenario S6 s6_one_node_offline
run_scenario S7 s7_two_nodes_offline
run_scenario S8 s8_malicious_proposer
run_scenario S9 s9_claim

# ----------------------------------------------------------------- report
CUR_SCENARIO=setup
if [ "$FOLLOW" = 1 ]; then
  proxy_post /release '{"clear":true}'
  log "--follow-mainnet: release cap cleared; the chain now follows new mainnet blocks (confirmation depth $DEPTH)"
fi
snap_logs final >/dev/null
docker logs "$PROXY_CONTAINER" > "$LOGS/btc_proxy.log" 2>&1 || true
curl -sf "$CONTROL/stats" > "$LOGS/btc_proxy_stats.json" 2>/dev/null || true

python3 - "$RESULTS_TSV" "$OUT/results.json" "$INIT" "$CHAIN_ID" <<'PY'
import json, sys
rows = []
for line in open(sys.argv[1]):
    name, status, secs, det = (line.rstrip("\n").split("\t") + [""] * 4)[:4]
    rows.append({"scenario": name, "status": status, "seconds": int(secs or 0), "detail": det})
json.dump({"chain_id": sys.argv[4], "btc_initial_height": int(sys.argv[3]), "results": rows}, open(sys.argv[2], "w"), indent=2)
print()
print("%-4s %-5s %6s  %s" % ("", "", "secs", "detail"))
for r in rows:
    d = r["detail"]
    print("%-4s %-5s %6d  %s" % (r["scenario"], r["status"], r["seconds"], d if len(d) < 160 else d[:157] + "..."))
bad = [r for r in rows if r["status"] == "FAIL"]
print("\n%d scenario(s), %d failed. Results: %s" % (len(rows), len(bad), sys.argv[2]))
sys.exit(1 if bad else 0)
PY
