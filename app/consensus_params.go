package app

// DefaultBlockMaxGas is the block.max_gas that `qbtcd init` and
// `qbtcd multi-node` write to genesis. CometBFT's default of -1 puts no limit
// on a block's gas. A one-UTXO free claim runs with types.FreeClaimBaseGas
// (450,000), so 200 of them take 90,000,000 of it.
const DefaultBlockMaxGas int64 = 100_000_000
