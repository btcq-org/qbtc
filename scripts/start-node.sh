#!/bin/sh
set -eux

rm -rf .qbtclocalnode/
mkdir -p .qbtclocalnode
APPD=./build/qbtcd
QBTC_HOME="$PWD/.qbtclocalnode"
$APPD config set client chain-id localnet-1 --home $QBTC_HOME
$APPD config set client keyring-backend test --home $QBTC_HOME
$APPD config set client output json --home $QBTC_HOME
yes | $APPD keys add validator --home $QBTC_HOME
VALIDATOR=$($APPD keys show validator -a --home $QBTC_HOME)
DENOM=uqbtc


$APPD init qbtc --chain-id localnet-1 --home $QBTC_HOME
$APPD config set app minimum-gas-prices 0.0025$DENOM --home $QBTC_HOME

$APPD genesis add-genesis-account $VALIDATOR "1000000000000000$DENOM" --home $QBTC_HOME
$APPD genesis gentx validator "1000000000$DENOM" --chain-id localnet-1 --keyring-backend test --home $QBTC_HOME 
$APPD genesis collect-gentxs --home $QBTC_HOME
$APPD genesis validate-genesis --home $QBTC_HOME
$APPD start --home $QBTC_HOME
