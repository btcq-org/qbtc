#!/usr/bin/env bash

set -e


echo "Generating gogo proto code"
cd proto

buf generate --template buf.gen.gogo.yaml

cp  btcq/common/*.pb.go ../common/
cp -r btcq/x/* ../x
rm -rf btcq/x
rm -f btcq/common/*.pb.go
