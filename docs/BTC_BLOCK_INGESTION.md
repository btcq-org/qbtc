# Bitcoin block ingestion

How qbtc learns about Bitcoin blocks, what the chain checks, and what it trusts the validators for.

## Flow

1. Each validator's bifrost waits until a Bitcoin block has `confirmation_depth` confirmations (default 6), fetches it from its own Bitcoin node with `getblock <hash> 0`, and builds a `BtcBlockCommit`: the 80-byte header and every transaction in block order, each in Bitcoin's serialization **without witness data**.
2. It signs the commit's proto encoding with its consensus key and gossips the signature with the gzip-compressed commit.
3. Bifrost groups attestations by block hash, height and the hash of the uncompressed commit. Once validators with more than 2/3 of the bonded power have signed the same commit, it hands the block to the validator node.
4. The block proposer injects the block as a `MsgBtcBlock`, which only the injection path can submit (`types.EBifrostSignerAddress`).

## What the chain checks

The block handler (`x/qbtc/keeper/handler_msg_report_block.go`, `btc_block.go`) accepts a block only if:

- The signer is the injection signer, and the height is the last processed height + 1.
- Validators with more than 2/3 of the bonded power signed the uncompressed commit.
- Every transaction is in canonical serialization without witness data. The chain recomputes each txid (the double SHA-256 of those bytes), so transaction contents are not taken on trust.
- The first transaction, and only the first, is a coinbase. No txid repeats (CVE-2012-2459), and the merkle root of the txids equals the header's.
- The header hashes to the reported block hash and links to the stored tip (`prev_block`).
- The header's difficulty bits follow Bitcoin's retarget rule (as btcd's `calcNextRequiredDifficulty`), and its hash meets that target.
- Where BIP34 applies, the coinbase encodes the block's height.

Not checked: the median-time-past and future-timestamp rules, and witness data. Breaking the timestamp rules would still need headers that meet the current difficulty. Witness data is not needed, because qbtc only reads inputs, output values and output scripts, all of which are in the txid.

## Genesis anchor

The chain does not start from Bitcoin's genesis block. `btc_initial_height` is the first Bitcoin height it processes, and genesis carries the block before it:

| Genesis field | Meaning |
|---|---|
| `btc_initial_height` | First Bitcoin height the chain processes |
| `btc_anchor_header` | 80-byte header of the block at `btc_initial_height - 1` |
| `btc_anchor_period_start_time` | Timestamp of the first block of the anchor's difficulty period (height a multiple of 2016), for the next retarget |

Without an anchor, no Bitcoin block is accepted. The chain applies Bitcoin mainnet's consensus rules; other networks are only used in tests. `qbtcd genesis validate` checks that the anchor header meets its own proof-of-work target. Validators must check that the anchor is the real block at `btc_initial_height - 1`. `ExportGenesis` writes the current tip as the anchor, so an exported chain continues at the next block. The multi-node testnet generator reads the anchor from its Bitcoin node; `genesis.md` shows how to set it by hand.

## Trust model

- The chain proves that a block is part of a chain of headers with real proof of work at the right difficulty, starting from the genesis anchor, and that the transactions it applies are exactly that block's.
- The validators still choose which branch to follow. More than 2/3 of the power could attest to a valid block that later leaves the best chain (for example a block they mined privately with real work), but they cannot invent transactions or outputs.
- There is no reorg handling. A processed block is final. If Bitcoin reorgs deeper than `confirmation_depth`, the next block does not link to the stored tip and ingestion stops until the chain is rolled back by an upgrade. Six confirmations make this very unlikely.
- A single Bitcoin block larger than half of qbtc's block space cannot be injected, which stops ingestion at that block (#164).

## Size

For block 923828 (1,391 transactions), the commit is 369 KB uncompressed and 268 KB gzipped, against 4.3 MB (1.2 MB gzipped) for the `getblock` JSON that validators signed before.
