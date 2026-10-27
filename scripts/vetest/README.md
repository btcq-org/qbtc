# Vote-extension scenario harness (`scripts/vetest`)

End-to-end checks of Bitcoin ingestion through ABCI vote extensions: four qbtc
validators run in Docker, each reads Bitcoin **mainnet** through a
fault-injecting JSON-RPC proxy, and `run.sh` asserts the behaviour from node
logs, chain state and the real mainnet hashes.

| File | Purpose |
|---|---|
| `run.sh` | orchestration and assertions (`--keep`, `--only`, ...) |
| `claim.sh` | claims one UTXO with a ZK proof on a network left running with `--keep` (see "Claiming your own UTXOs") |
| `preflight.sh` | checks tools, Docker, ports, disk, RAM and reachability (`run.sh --check`) |
| `btc_proxy.py` | stdlib-only bitcoind-style RPC server over mempool.space / Blockstream (or a real bitcoind), with per-validator fault modes |
| `vetest_lib.py` | log analysis, genesis patching and claim message helpers |
| `Dockerfile` | qbtcd image; `EXTRA_TAGS=vetest_malicious` builds the malicious-proposer variant |

## Server prerequisites

Linux with bash, GNU coreutils, `curl`, `git`, `python3` (3.8+), Docker with
compose v2 and BuildKit, and Go 1.26.x on the host (only used to build `zkprover`
and `tss-emulator` for S9). Roughly 15 GB free disk (images, about 0.5 GB of
mainnet blocks, the 2.4 GB Hermez ptau and the proving key), 16 GB RAM or more
for S9 (the PLONK setup and proof use several GB), and outbound access to
mempool.space or blockstream.info, Docker Hub, GitHub (libwasmvm), the Go
module proxy and circom.info. Free host ports: 26657/26654/26651/26648 (CometBFT
RPC), 9090/9088/9086/9084 (gRPC), 1317..1314, 18449, 18450 and 18480.

Run `scripts/vetest/preflight.sh` first (`SKIP_ZK=1` when skipping S9).

## Running

```bash
scripts/vetest/preflight.sh
scripts/vetest/run.sh                     # all scenarios, tears everything down at the end
scripts/vetest/run.sh --only S3,S9        # selected scenarios
scripts/vetest/run.sh --keep              # leave the network up for inspection
scripts/vetest/run.sh --no-build          # reuse the qbtcd-vetest:* images
scripts/vetest/run.sh --vendor            # build from a host-vendored context (see below)
scripts/vetest/run.sh --clean             # remove containers, network and out/
```

Re-runs are idempotent: leftovers of an earlier run are removed first. Results
are printed as a table and written to `out/results.json`; per-scenario logs are
`out/S*.log`, node log snapshots are under `out/logs/<tag>/node_<i>.log` and
the proxy log and stats are `out/logs/btc_proxy*`. Exit status is 1 if any
scenario failed.

Environment knobs (defaults in the script): `BACKLOG` (150), `BATCH` blocks
released per scenario phase (14), `ENABLE_HEIGHT` (10), `CONFIRMATION_DEPTH`
(6), `POLL_INTERVAL` (2s), `UPSTREAM`, `BTC_INITIAL_HEIGHT`.

`--vendor` runs `go mod vendor` in a temporary copy of the repository (tracked
plus untracked-not-ignored files) and builds with `-mod=vendor`; use it when
the Docker build cannot download Go modules. The default build lets Docker
download them. Only `./cmd/qbtcd` is built.

### Bitcoin source

`UPSTREAM=esplora:https://mempool.space/api` is the default
(`https://blockstream.info/api` is always added as a fallback; an endpoint that
errors or downloads too slowly is demoted for ten minutes, and 429/5xx are
retried with backoff). Comma separated URLs are allowed. To use a real
bitcoind:

```bash
UPSTREAM=rpc:http://user:pass@host:8332 scripts/vetest/run.sh
```

The host must be reachable from the proxy container. Blocks are cached on disk
in `.cache/btc` (gitignored), so every block is downloaded once, also across
runs. `run.sh` prefetches about 280 blocks (roughly 450 MB) before starting the
chain; the first run is bounded by upstream speed.

The chain starts at a mainnet height chosen so that `BACKLOG` confirmed blocks
are waiting at activation; the proxy then hands out further blocks in batches
(`POST /release`) so each scenario has fresh blocks to ingest.

Proxy control (port 18450, used by `run.sh`; handy with `--keep`):
`POST /mode {"validator":3,"mode":"ok|down|fork|frozen","from_height":N}`,
`POST /reset`, `POST /release {"height":H}`, `GET /truth/<height>`, `GET /tip`,
`GET /stats`. `python3 btc_proxy.py --selftest` checks upstream access, block
parsing and the fault modes.

## Scenarios

Validators have equal stake, so one validator is 25% of the power.

| | Checks |
|---|---|
| S1 Activation | state at each qbtc height: no Bitcoin block is processed up to the enable height (10); the first injection happens at height >= 11 |
| S2 Happy path | the backlog is fully ingested; every applied hash equals the mainnet hash; >= 10 consecutive heights tallied with power == total; qbtc block time and extension / inject tx / evidence sizes recorded |
| S3 One Bitcoin node down | validator 3's proxy fails every call: ingestion continues with power 3/4; after restoring, tallies return to 4/4 |
| S4 One validator on a fork | validator 3 gets the block of height-1 at each height: tallies with two candidates (3/4 mainnet, 1/4 fork); applied hashes equal mainnet; restored -> 4/4 |
| S5 Three Bitcoin nodes down | consensus height advances >= 5 while the last processed Bitcoin height stays; restoring resumes ingestion |
| S6 One validator offline | `docker stop` validator 3: consensus and ingestion continue (3/4); restart: it catches up, refills its block cache (`btc block cached`) and its votes return (4/4) |
| S7 Two validators offline | with two of four validators stopped (50% < 2/3) the chain halts for >= 35 s; after restarting both it recovers and ingestion continues |
| S8 Malicious proposer | validator 0 restarted on the `vetest_malicious` image with `QBTC_VETEST_MALICIOUS=forge`, then `noevidence`: the other nodes log `rejecting proposal`, the chain keeps committing through other proposers, applied hashes equal mainnet; the honest image is restored afterwards |
| S9 Claim | a fresh secp256k1 key (signing through the TSS emulator) owns a P2WPKH genesis UTXO; `zkprover` makes the PLONK proof bound to the chain ID and a fresh qbtc address; `MsgClaimWithProof` is submitted with `tx qbtc claim-with-proof`; the destination balance equals the entitled amount, the UTXO's entitled amount is 0, and an identical second claim is rejected |

S7 note: with four equal validators, two offline leaves 50% of the power, so the
chain halts (it would also halt at exactly 2/3, since more than 2/3 is required).

### S9 details

The genesis gets the UTXO (`utxos`) and the verifying key (`zk_verifying_key`).
On the first run `zkprover setup` downloads the Hermez 2^21 powers-of-tau file
(2.4 GB, hash-checked) and builds the keys; they are cached in `.cache/zk`
(gitignored) and reused. The key is a production-setup key, as genesis
validation requires. The proof is generated on the host (about half a minute
on a many-core machine) and the claim is broadcast from validator 0's key (the
ante handler waives the fee) with the fresh address as `receiver`.

## Claiming your own UTXOs

`claim.sh` claims one UTXO on a network left running by `run.sh --keep`, with the
same machinery as S9 (TSS emulator, cached `zkprover` and PLONK setup,
`tx qbtc claim-with-proof`). `run.sh` writes the network settings to
`out/network.env` once the chain is up; `claim.sh` reads them. The ZK material
is built by `run.sh` only when S9 is selected or `--genesis-utxo` is given.

**Warning: use a fresh key that holds a small amount.** The key is handled by a
test-grade tool on a shared server. `claim.sh` never prints it, and reads it
from `--key-file` (preferred; `--wif` is visible in `ps`, `--wif -` reads stdin).
It reaches the local TSS emulator only through its `TSS_PRIVATE_KEY` environment
variable, and any temporary copy is 0600 and deleted on exit. The proof also
reveals nothing about the key, but the chain is a test chain: do not use a key
that protects real funds.

```bash
umask 077; echo 'KwDi...your-WIF' > ~/claim.key       # compressed WIF or 64 hex chars
scripts/vetest/claim.sh <txid> <vout> --key-file ~/claim.key
#   optional: --dest <qbtc address> | --dest-key <keyring name>   (default: a new key claim-dest-<txid8>-<vout>)
#             --from <keyring name>                              (default validator0, pays the fee-free tx)
#             --tss-port <port>                                  (default: first free port above 18480)
```

It derives the Hash160 from the key, checks with `qbtcd q qbtc utxo` that the
UTXO exists, is locked to that key and has a non-zero entitled amount, proves,
submits, waits for the result and prints the destination balance before and
after plus the UTXO's entitled amount. A UTXO is only in chain state if it is in
genesis or in a Bitcoin block the chain ingested (height >= `btc_initial_height`
and confirmed `CONFIRMATION_DEPTH` = 6 blocks deep); otherwise `claim.sh` fails
and says so. P2PKH and P2WPKH (compressed key) are supported.

### (a) A fresh UTXO, while the chain follows mainnet

By default the proxy caps the Bitcoin tip so scenarios control ingestion. To keep
following mainnet, start with `--follow-mainnet` (implies `--keep`), which clears
the cap (`POST /release {"clear":true}`) after the scenarios:

```bash
scripts/vetest/run.sh --follow-mainnet
# or, on a network already kept: curl -X POST -d '{"clear":true}' http://127.0.0.1:18450/release
```

The chain ingests blocks at the pace of mainnet (about 10 minutes each, backlog
first). Send a small amount on **mainnet** to the P2WPKH or P2PKH address of your
fresh key (`claim.sh --show-address --key-file ~/claim.key` prints its P2WPKH and P2PKH addresses), note the txid and
output index, and about an hour later (the block plus 6 confirmations plus
ingestion) claim it:

```bash
scripts/vetest/claim.sh <txid> <vout> --key-file ~/claim.key
```

Until then `claim.sh` reports that the UTXO is not in chain state; check progress
with `docker exec vetest-node_0-1 qbtcd q qbtc last-processed-block --node tcp://localhost:26657`.
The entitled amount of an ingested output is computed by the chain (it can be
lower than the output amount).

### (b) An older UTXO via `--genesis-utxo`

Blocks older than `btc_initial_height` are never ingested, so put the UTXO in
genesis. The flag is repeatable and adds to the S9 test UTXO; the amount is the
output value in satoshis and becomes the entitled amount:

```bash
scripts/vetest/run.sh --keep \
  --genesis-utxo <txid>:<vout>:<amount_sats>:<bc1q... or 1... address> \
  --genesis-utxo <txid2>:<vout2>:<amount_sats>:<address2>
scripts/vetest/claim.sh <txid> <vout> --key-file ~/claim.key
```

Arguments are validated before anything starts (64-hex txid, numeric vout,
positive amount, valid mainnet P2PKH `1...` or P2WPKH `bc1q...` address). Add
`--follow-mainnet` instead of `--keep` to combine both paths. A claim is final:
the UTXO's entitled amount becomes 0, and `--clean` or a re-run wipes the chain.

## Expected runtime

First run: image builds 5-10 minutes (two images with S8), block prefetch
about 5-15 minutes depending on upstream speed, ZK setup 2-5 minutes plus the
ptau download. Later runs reuse the caches. The scenarios themselves take
about 25-40 minutes in total (each waits for ingestion of 10 blocks per phase;
S7 includes a 50 s halt; S9 about 2 minutes). A full first run is roughly
1-1.5 hours.

## Assumptions about the chain logs

The assertions parse these messages (see the design document): `btc vote tally`
(`btc_height`, `hash`, `power`, `total`), `btc block processed` (`height`,
`hash`), `rejecting proposal`, `injecting btc blocks`, `btc vote extension`
and `btc block cached`, plus the `last-processed-block` query. If a key is
renamed, adjust `vetest_lib.py`.
