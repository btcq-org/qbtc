#!/usr/bin/env bash
# Checks that this machine can run tests/vetest/run.sh: tools, Docker, free
# ports, disk and memory, and reachability of everything the run downloads.
# Makes only small requests (HEAD / a few bytes); nothing is built or started.
#
#   tests/vetest/preflight.sh            # or: tests/vetest/run.sh --check
#   SKIP_ZK=1 tests/vetest/preflight.sh  # skip the ZK checks (when not running S9)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FAILS=0
WARNS=0
ok()   { printf '  ok    %s\n' "$*"; }
warn() { printf '  WARN  %s\n' "$*"; WARNS=$((WARNS + 1)); }
bad()  { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

echo "tools"
for t in bash docker git curl python3 sed tar awk openssl; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t"; else
    if [ "$t" = openssl ] && [ "${SKIP_ZK:-0}" = 1 ]; then warn "$t missing (only needed for S9)"; else bad "$t not found"; fi
  fi
done
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' && ok "python3 $(python3 -V 2>&1 | cut -d' ' -f2) (>= 3.8)" || bad "python3 >= 3.8 required"
fi
if command -v go >/dev/null 2>&1; then
  gv=$(go env GOVERSION 2>/dev/null)
  case "$gv" in go1.26*|go1.27*|go1.28*|go1.29*) ok "go $gv" ;; *) warn "go $gv; go.mod needs 1.26.x (a newer toolchain is fetched automatically if GOTOOLCHAIN=auto and the Go proxy is reachable)" ;; esac
else
  bad "go not found (needed on the host to build zkprover and the tss emulator for S9)"
fi

echo "docker"
if docker info >/dev/null 2>&1; then
  ok "daemon reachable ($(docker version --format '{{.Server.Version}}' 2>/dev/null))"
  if docker compose version >/dev/null 2>&1; then ok "docker compose v2 ($(docker compose version --short 2>/dev/null))"; else bad "docker compose v2 plugin missing"; fi
  docker buildx version >/dev/null 2>&1 && ok "buildx (cache mounts)" || warn "buildx not found; the Dockerfile uses BuildKit cache mounts"
else
  bad "cannot talk to the Docker daemon (is it running, and does this user have access?)"
fi

echo "ports (must be free on 127.0.0.1)"
for p in 26657 26654 26651 26648 9090 9088 9086 9084 1317 1316 1315 1314 18449 18450 18480; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then bad "port $p is already in use"; fi
done
[ "$FAILS" = 0 ] && ok "no conflicts found"

echo "resources"
free_gb=$(df -Pk "$SCRIPT_DIR" | awk 'NR==2 {print int($4 / 1048576)}')
need_gb=15; [ "${SKIP_ZK:-0}" = 1 ] && need_gb=8
if [ "${free_gb:-0}" -ge "$need_gb" ]; then ok "${free_gb} GB free here (need ~$need_gb: images, ~0.5 GB of blocks, 2.4 GB ptau + keys)"; else bad "only ${free_gb} GB free here, need ~$need_gb"; fi
if [ -r /proc/meminfo ]; then
  mem_gb=$(awk '/MemTotal/ {print int($2 / 1048576)}' /proc/meminfo)
  if [ "$mem_gb" -ge 16 ]; then ok "${mem_gb} GB RAM"; else warn "${mem_gb} GB RAM; the ZK setup/proof (S9) wants ~16 GB, plus 4 validators"; fi
fi

echo "network (small requests)"
chk() { # chk <description> <url> [curl args...]
  local d=$1 u=$2; shift 2
  # any HTTP answer counts as reachable (Docker Hub's registry answers 401 without credentials);
  # only connection failures and timeouts are errors
  local code
  code=$(curl -sS -L --max-time 20 -o /dev/null -w '%{http_code}' "$@" "$u" 2>/dev/null || true)
  if [ -n "$code" ] && [ "$code" != 000 ]; then ok "$d"; else bad "$d unreachable ($u)"; fi
}
chk "mempool.space (bitcoin upstream)" https://mempool.space/api/blocks/tip/height
chk "blockstream.info (fallback upstream)" https://blockstream.info/api/blocks/tip/height
chk "Docker Hub (python:3.12-alpine, golang:1.26-alpine, alpine)" https://registry-1.docker.io/v2/ -I
chk "GitHub (libwasmvm release download in the Dockerfile)" https://github.com/CosmWasm/wasmvm/releases/download/v2.2.4/libwasmvm_muslc.x86_64.a -I
chk "Go module proxy (Docker build and host go build)" https://proxy.golang.org/github.com/cosmos/cosmos-sdk/@v/list
if [ "${SKIP_ZK:-0}" != 1 ]; then
  chk "circom.info (Hermez ptau for the ZK setup, 2.4 GB)" https://circom.info/powersOfTau28_hez_final_21.ptau -I
fi
if docker info >/dev/null 2>&1; then
  if docker run --rm --pull=missing alpine:3.23 wget -q -T 15 -O /dev/null https://blockstream.info/api/blocks/tip/height 2>/dev/null; then
    ok "containers can reach the Bitcoin upstream"
  else
    bad "a container cannot reach blockstream.info (the proxy runs in a container); check Docker DNS/proxy settings"
  fi
fi

echo "repository"
[ -f "$ROOT/go.mod" ] && ok "repository root $ROOT" || bad "go.mod not found above $SCRIPT_DIR"

echo
if [ "$FAILS" -gt 0 ]; then echo "preflight: $FAILS failure(s), $WARNS warning(s)"; exit 1; fi
echo "preflight: ok ($WARNS warning(s))"
