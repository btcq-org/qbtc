#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="${REPO_ROOT}/docs/static/openapi.json"

cd "${REPO_ROOT}/proto"

echo "Generating merged OpenAPI spec from proto files"
# qbtc/ebifrost is the localhost-only validator-internal control plane; it
# isn't reachable via REST/grpc-gateway and shouldn't appear in the public spec.
go tool github.com/bufbuild/buf/cmd/buf generate \
  --template buf.gen.openapi.yaml \
  --exclude-path qbtc/ebifrost

mkdir -p "$(dirname "${OUT_FILE}")"
jq '.info = {title: "qbtc Chain HTTP API", description: "REST and gRPC-gateway endpoints exposed by qbtcd.", contact: {name: "btcq"}, version: "1.0.0"}' \
  openapi.swagger.json > "${OUT_FILE}"
rm openapi.swagger.json

echo "OpenAPI spec written to ${OUT_FILE}"
