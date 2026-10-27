#!/usr/bin/env bash
# Claim one UTXO with a ZK proof on a network that run.sh left running (--keep).
#
#   claim.sh <txid> <vout> (--wif <WIF> | --key-file <file>) \
#            [--dest <qbtc address> | --dest-key <keyring name>] \
#            [--from <keyring name, default validator0>] [--tss-port <port>]
#   claim.sh --show-address (--wif <WIF> | --key-file <file>)   # print the key's addresses and exit
#
# --key-file holds the WIF or 64 hex characters of the private key (preferred: --wif is
# visible in `ps`; `--wif -` reads the key from stdin). The key is never printed or logged:
# it only reaches the local TSS emulator through its TSS_PRIVATE_KEY environment variable,
# any temporary copy is created 0600 and removed on exit.
#
# Needs: a network started by run.sh --keep (reads out/network.env), the zkprover and
# tss-emulator binaries and the ZK setup in .cache (run.sh builds them when it runs with
# --genesis-utxo or S9), docker, curl, python3.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$SCRIPT_DIR/vetest_lib.py"
ENV_FILE="$SCRIPT_DIR/out/network.env"

usage() { sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
die() { echo "ERROR: $*" >&2; exit 1; }
say() { printf '%s\n' "$*" >&2; }

TXID=""; VOUT=""; WIF=""; KEY_FILE=""; DEST=""; DEST_KEY=""; FROM="validator0"; TSS_PORT_ARG=""; SHOW=0
POS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --wif) WIF="${2:?--wif needs a value (or - for stdin)}"; shift ;;
    --key-file) KEY_FILE="${2:?--key-file needs a path}"; shift ;;
    --dest) DEST="${2:?--dest needs a qbtc address}"; shift ;;
    --dest-key) DEST_KEY="${2:?--dest-key needs a keyring name}"; shift ;;
    --from) FROM="${2:?--from needs a keyring name}"; shift ;;
    --tss-port) TSS_PORT_ARG="${2:?--tss-port needs a port}"; shift ;;
    --show-address) SHOW=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; die "unknown option: $1" ;;
    *) POS+=("$1") ;;
  esac
  shift
done
if [ "$SHOW" = 1 ]; then
  TXID=0000000000000000000000000000000000000000000000000000000000000000; VOUT=0
else
  [ "${#POS[@]}" -eq 2 ] || { usage >&2; die "need <txid> <vout>"; }
  TXID="${POS[0]}"; VOUT="${POS[1]}"
  [[ "$TXID" =~ ^[0-9a-fA-F]{64}$ ]] || die "txid must be 64 hex characters"
  [[ "$VOUT" =~ ^[0-9]+$ ]] || die "vout must be a non-negative integer"
  TXID=$(printf '%s' "$TXID" | tr 'A-F' 'a-f')
fi
{ [ -n "$WIF" ] || [ -n "$KEY_FILE" ]; } || { usage >&2; die "give the key with --wif or --key-file"; }
{ [ -z "$WIF" ] || [ -z "$KEY_FILE" ]; } || die "use only one of --wif and --key-file"
{ [ -z "$DEST" ] || [ -z "$DEST_KEY" ]; } || die "use only one of --dest and --dest-key"
[ -z "$TSS_PORT_ARG" ] || [[ "$TSS_PORT_ARG" =~ ^[0-9]+$ ]] || die "--tss-port must be a number"
for t in docker curl python3; do command -v "$t" >/dev/null 2>&1 || die "missing prerequisite: $t"; done

# ------------------------------------------------------------- network settings
[ -f "$ENV_FILE" ] || die "$ENV_FILE not found: start a network first with scripts/vetest/run.sh --keep (the file is written once the chain is up)"
# shellcheck disable=SC1090
. "$ENV_FILE"
PROJECT=$VETEST_PROJECT; CHAIN_ID=$VETEST_CHAIN_ID; CACHE=$VETEST_CACHE; OUT=$VETEST_OUT; NET=$VETEST_NET
INIT=$VETEST_INIT; BASE_TSS_PORT=$VETEST_TSS_PORT
NODE="${PROJECT}-node_0-1"
HOME_DIR=/qbtc_data/.qbtc
RPC="tcp://localhost:26657"          # validator 0 inside its container (rpc_port 0 in run.sh)

jget() { python3 "$LIB" jget "$@"; }
qq() { docker exec "$NODE" qbtcd q "$@" --node "$RPC" -o json; }
kk() { docker exec "$NODE" qbtcd keys "$@" --keyring-backend test --home "$HOME_DIR"; }

[ "$(docker inspect -f '{{.State.Running}}' "$NODE" 2>/dev/null || true)" = true ] \
  || die "container $NODE is not running: the network is down (restart it with run.sh --keep)"
[ "$(qq qbtc last-processed-block 2>/dev/null | jget - height '?' 2>/dev/null || echo '?')" != '?' ] \
  || die "the chain on $NODE does not answer queries yet (is it producing blocks?)"

ZKPROVER="$CACHE/bin/zkprover"; TSS_BIN="$CACHE/bin/tss-emulator"; SETUP="$CACHE/zk/setup"
for f in "$ZKPROVER" "$TSS_BIN" "$SETUP/verifying.key" "$SETUP/proving.key" "$SETUP/circuit.cs"; do
  [ -f "$f" ] || die "missing $f: run.sh has not prepared the ZK material. Re-run it with --genesis-utxo (or S9 selected) so zkprover, tss-emulator and the setup are built into $CACHE"
done

# ----------------------------------------------------------------- key handling
umask 077
WORK="$OUT/claim/manual-${TXID:0:12}-$VOUT"
mkdir -p "$WORK"
chmod 700 "$WORK"
TMP_KEY=""; TSS_PID=""
cleanup() {
  [ -z "$TSS_PID" ] || kill "$TSS_PID" 2>/dev/null || true
  [ -z "$TMP_KEY" ] || rm -f "$TMP_KEY"
  unset KEYHEX WIF 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if [ -n "$KEY_FILE" ]; then
  [ -r "$KEY_FILE" ] || die "cannot read key file $KEY_FILE"
  if [ -n "$(find "$KEY_FILE" -maxdepth 0 -perm /077 2>/dev/null)" ]; then
    say "WARNING: $KEY_FILE is readable by other users (chmod 600 it)"
  fi
  KEY_SRC="$KEY_FILE"
else
  TMP_KEY=$(mktemp "$WORK/key.XXXXXX")          # 0600 (mktemp + umask 077)
  chmod 600 "$TMP_KEY"
  if [ "$WIF" = "-" ]; then cat > "$TMP_KEY"; else printf '%s\n' "$WIF" > "$TMP_KEY"; fi
  WIF=""
  KEY_SRC="$TMP_KEY"
fi
KEYHEX=$(python3 "$LIB" key-hex "$KEY_SRC") || die "unusable private key"
[ -z "$TMP_KEY" ] || { rm -f "$TMP_KEY"; TMP_KEY=""; }   # the hex is in memory only from here

# ------------------------------------------------------------------ TSS emulator
tss_info() { curl -sf --max-time 3 "http://127.0.0.1:$1/info" 2>/dev/null; }
if [ -n "$TSS_PORT_ARG" ]; then
  PORT=$TSS_PORT_ARG
else
  PORT=$((BASE_TSS_PORT + 1))
  while tss_info "$PORT" >/dev/null; do PORT=$((PORT + 1)); done      # first free port above run.sh's emulator
fi
if tss_info "$PORT" > "$WORK/info.json"; then
  say "reusing the TSS emulator already listening on 127.0.0.1:$PORT"
else
  # the key goes in through the environment, not argv, so it is not visible in ps
  TSS_PRIVATE_KEY="$KEYHEX" "$TSS_BIN" --port "127.0.0.1:$PORT" > "$WORK/tss.log" 2>&1 &
  TSS_PID=$!
  end=$((SECONDS + 20))
  until tss_info "$PORT" > "$WORK/info.json"; do
    [ "$SECONDS" -ge "$end" ] && die "tss-emulator did not start (see $WORK/tss.log)"
    kill -0 "$TSS_PID" 2>/dev/null || die "tss-emulator exited (see $WORK/tss.log)"
    sleep 1
  done
fi
unset KEYHEX
umask 022                                        # the claim message must be readable inside the container
HASH160=$(jget "$WORK/info.json" address_hash)
[[ "$HASH160" =~ ^[0-9a-f]{40}$ ]] || die "the emulator returned no address hash"
say "key address hash (Hash160): $HASH160"
say "  P2WPKH: $(python3 "$LIB" bech32-p2wpkh "$HASH160")"
say "  P2PKH:  $(python3 "$LIB" base58-p2pkh "$HASH160")"
if [ "$SHOW" = 1 ]; then exit 0; fi

# ------------------------------------------------------------------ the UTXO
if ! UTXO_JSON=$(qq qbtc utxo --txid "$TXID" --vout "$VOUT" 2>&1); then
  LPB=$(qq qbtc last-processed-block 2>/dev/null | jget - height '?' 2>/dev/null || echo '?')
  die "UTXO $TXID:$VOUT is not in chain state.
  The chain only knows UTXOs that are in genesis or in a Bitcoin block it has ingested, i.e. at
  height >= btc_initial_height ($INIT) and at least ${VETEST_DEPTH:-6} confirmations deep (last processed height: $LPB).
  - fresh UTXO: wait until the chain has processed its block (run.sh --follow-mainnet keeps ingesting);
  - older UTXO: restart the network with run.sh --keep --genesis-utxo $TXID:$VOUT:<sats>:<address>.
  query output: $(printf '%s' "$UTXO_JSON" | head -c 300)"
fi
ENT=$(printf '%s' "$UTXO_JSON" | jget - utxo.entitled_amount 0)
[[ "$ENT" =~ ^[0-9]+$ ]] || die "unexpected entitled amount in the query result"
[ "$ENT" != 0 ] || die "UTXO $TXID:$VOUT has an entitled amount of 0: it was already claimed (or is not claimable)"
SPK=$(printf '%s' "$UTXO_JSON" | jget - utxo.script_pub_key.hex "")
if [ -n "$SPK" ]; then
  case "$SPK" in
    "0014$HASH160"|"76a914${HASH160}88ac") ;;
    *) die "UTXO $TXID:$VOUT is locked to a different key (script $SPK); this key's hash is $HASH160" ;;
  esac
fi
say "UTXO $TXID:$VOUT found, entitled amount $ENT"

# ------------------------------------------------------------ destination, claimer
if [ -z "$DEST" ]; then
  if [ -z "$DEST_KEY" ]; then DEST_KEY="claim-dest-${TXID:0:8}-$VOUT"; fi
  if ! DEST=$(kk show "$DEST_KEY" -a 2>/dev/null); then
    kk add "$DEST_KEY" --output json > "$WORK/dest_key.json" 2>/dev/null || die "could not create the keyring key $DEST_KEY"
    DEST=$(kk show "$DEST_KEY" -a)
    say "created keyring key $DEST_KEY on $NODE; its mnemonic is in $WORK/dest_key.json (0600): keep it if the funds matter"
  fi
fi
CLAIMER=$(kk show "$FROM" -a 2>/dev/null) || die "keyring key '$FROM' not found on $NODE (--from)"
[ -n "$DEST" ] && [ -n "$CLAIMER" ] || die "could not resolve the destination or claimer address"
bal() { qq bank balances "$DEST" 2>/dev/null | jget - balances.0.amount 0 2>/dev/null || echo 0; }
BAL_BEFORE=$(bal)
say "destination $DEST (balance before: $BAL_BEFORE), claimer key $FROM ($CLAIMER)"

# ------------------------------------------------------------------ proof, message
say "generating the PLONK proof (about half a minute, several GB of RAM)..."
t0=$SECONDS
"$ZKPROVER" prove --tss-url "http://127.0.0.1:$PORT" --qbtc-address "$DEST" --chain-id "$CHAIN_ID" \
  --address-hash "$HASH160" --setup-dir "$SETUP" -o "$WORK/proof.json" > "$WORK/prove.log" 2>&1 \
  || die "zkprover prove failed, see $WORK/prove.log"
say "proof generated in $((SECONDS - t0))s"
MSG_NAME="claim_msg_${TXID:0:12}_${VOUT}.json"
python3 "$LIB" claim-msg --proof "$WORK/proof.json" --claimer "$CLAIMER" --receiver "$DEST" \
  --txid "$TXID" --vout "$VOUT" --out "$NET/validator0/$MSG_NAME"

# ------------------------------------------------------------------ submit, wait
out=$(docker exec "$NODE" qbtcd tx qbtc claim-with-proof "$HOME_DIR/$MSG_NAME" \
      --from "$FROM" --keyring-backend test --home "$HOME_DIR" --chain-id "$CHAIN_ID" \
      --node "$RPC" --gas 2000000 --fees "0qbtc" -y --broadcast-mode sync -o json 2>&1 || true)
printf '%s\n' "$out" > "$WORK/tx_last.json"
code=$(printf '%s' "$out" | jget - code "" 2>/dev/null || true)
hash=$(printf '%s' "$out" | jget - txhash "" 2>/dev/null || true)
[ -n "$hash" ] || die "the transaction was not accepted: $(printf '%s' "$out" | head -c 400)"
if [ -n "$code" ] && [ "$code" != 0 ]; then
  die "the transaction was rejected in CheckTx (code $code): $(printf '%s' "$out" | jget - raw_log '' 2>/dev/null | head -c 400)"
fi
say "submitted tx $hash, waiting for it to be included..."
RES=""
end=$((SECONDS + 90))
while [ "$SECONDS" -lt "$end" ]; do
  if qq tx "$hash" > "$WORK/tx_result.json" 2>/dev/null; then RES=$(jget "$WORK/tx_result.json" code 0); break; fi
  sleep 2
done
[ -n "$RES" ] || die "timed out waiting for tx $hash"
[ "$RES" = 0 ] || die "the claim failed on chain (code $RES): $(jget "$WORK/tx_result.json" raw_log '' | head -c 400)"

BAL_AFTER=$(bal)
ENT_AFTER=$(qq qbtc utxo --txid "$TXID" --vout "$VOUT" | jget - utxo.entitled_amount 0)
echo "claim accepted (tx $hash)"
echo "destination:              $DEST"
echo "balance before:           $BAL_BEFORE"
echo "balance after:            $BAL_AFTER"
echo "UTXO entitled amount now: $ENT_AFTER"
