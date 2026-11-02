#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="${REPO_ROOT}/docs/static/openapi.json"

cd "${REPO_ROOT}/proto"

echo "Generating merged OpenAPI spec from proto files"
go tool github.com/bufbuild/buf/cmd/buf generate \
  --template buf.gen.openapi.yaml

mkdir -p "$(dirname "${OUT_FILE}")"
jq '.info = {
      title: "qbtc Chain HTTP API",
      description: "REST endpoints exposed by qbtcd through grpc-gateway. This spec documents the chain-specific Query routes only; for transaction submission and the standard Cosmos SDK module routes (auth, bank, gov, staking, tx broadcast, ...) refer to the Cosmos SDK swagger.",
      contact: {name: "btcq"},
      version: "1.0.0"
    }' openapi.swagger.json > "${OUT_FILE}"
rm openapi.swagger.json

echo "OpenAPI spec written to ${OUT_FILE}"
