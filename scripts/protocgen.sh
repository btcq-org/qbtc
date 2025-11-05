#!/usr/bin/env bash

set -e


echo "Generating gogo proto code"
cd proto

buf generate --template buf.gen.gogo.yaml

cp  github.com/btcq-org/qbtc/common/*.pb.go ../common/
cp -r github.com/btcq-org/qbtc/x/* ../x
rm -rf github.com
