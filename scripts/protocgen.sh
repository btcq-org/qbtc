#!/usr/bin/env bash

set -e


echo "Generating gogo proto code"
cd proto

buf generate --template buf.gen.gogo.yaml

cp  github.com/btcq-org/btcq/common/*.pb.go ../common/
cp -r github.com/btcq-org/btcq/x/* ../x
rm -rf github.com
