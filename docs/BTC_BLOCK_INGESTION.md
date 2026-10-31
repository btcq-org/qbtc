# Bitcoin block ingestion

How qbtc learns about Bitcoin blocks, what the chain checks, and what it trusts the validators for.

## Flow

1. Each validator's qbtcd runs a Bitcoin reader (`x/qbtc/btcreader`, enabled by `[btc_reader] enable = true` in `app.toml`). It reads the last processed Bitcoin height from committed state and fetches the following blocks from its own Bitcoin node with `getblock <hash> 0`, once they have `confirmation_depth` confirmations (default 6, the block itself counts as one). It checks each block locally (block hash, merkle root), builds a `BtcBlockCommit` (the 80-byte header and every transaction in block order, each in Bitcoin's serialization **without witness data**) and caches up to `max_cached_blocks`. Cached heights that are processed, or whose hash changed on the node, are dropped. Only the reader calls the Bitcoin node; consensus code reads the cache.
2. In `ExtendVote`, a validator lists its cached blocks, consecutive from the next unprocessed height and at most 16 (`MaxBtcBlockVotes`), as `(height, hash, sha256(uncompressed commit))`. `VerifyVoteExtension` checks the format only (at most 2048 bytes, at most 16 votes, no repeated height, a 32-byte commit hash, a 64-character lowercase hex hash) and never depends on the local Bitcoin node.
3. In `PrepareProposal`, the proposer tallies the previous height's extended commit. For consecutive heights from the next unprocessed one, it includes a block when validators with more than 2/3 of the commit's power voted for one `(hash, commit hash)` and the proposer holds a matching commit. It stops at the first height that fails, after 8 blocks (`MaxBtcBlocksPerMsg`), or when the next block would exceed half of `MaxTxBytes`. Validators attest twice as many heights as one block processes because an extension is built on the state before the block it votes on: with fewer, the proposer after a block that processed 8 would find no attested heights past them, and only every other block would carry Bitcoin blocks.
4. The proposer injects one `MsgBtcBlock` carrying all the included blocks and the marshaled `ExtendedCommitInfo` once. Only the injection path can submit it (`types.BtcBlockSignerAddress`). With no qualifying block, nothing is injected.

Vote extensions are active for a block when `vote_extensions_enable_height` (consensus parameter `abci`) is not 0 and the block's height is greater than it, because a proposal uses the previous height's extensions. Before that, no `MsgBtcBlock` is accepted.

## What the chain checks

`ProcessProposal` rejects a proposal if a `MsgBtcBlock` is outside an injected transaction, if it holds more than one `MsgBtcBlock`, if vote extensions are not active, or if the vote evidence below is invalid. The handler (`x/qbtc/keeper/handler_msg_report_block.go`, `btc_block.go`) repeats these checks in `FinalizeBlock`. The message is atomic: one failing block fails all of it.

- The signer is the injection signer, and vote extensions are active.
- The extended commit is valid for this block's last commit (`baseapp.ValidateVoteExtensions`): same round, validators and powers, every extension signature valid, and signed votes carry more than 2/3 of the power.
- For each block, validators with more than 2/3 of the commit's power voted for exactly its hash and the sha256 of its uncompressed commit. A validator counts once per height, and only commit votes with a decodable extension count.
- Heights run consecutively from the last processed height + 1.
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
- The validators still choose which branch to follow. More than 2/3 of the power could vote for to a valid block that later leaves the best chain (for example a block they mined privately with real work), but they cannot invent transactions or outputs.
- There is no reorg handling. A processed block is final. If Bitcoin reorgs deeper than `confirmation_depth`, the next block does not link to the stored tip and ingestion stops until the chain is rolled back by an upgrade. Six confirmations make this very unlikely.
- A single Bitcoin block larger than half of qbtc's block space cannot be injected, which stops ingestion at that block (#164).

## Size

For block 923828 (1,391 transactions), the commit is 369 KB uncompressed and 268 KB gzipped, against 4.3 MB (1.2 MB gzipped) for the `getblock` JSON used before.
