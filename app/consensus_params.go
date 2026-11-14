package app

// DefaultBlockMaxGas is the block.max_gas that `qbtcd init` and
// `qbtcd multi-node` write to genesis. CometBFT's default of -1 puts no limit
// on a block's gas. A full block of MaxClaimsPerBlock (200) one-UTXO claims,
// at types.FreeClaimBaseGas each, takes 90,000,000 of it.
const DefaultBlockMaxGas int64 = 100_000_000
