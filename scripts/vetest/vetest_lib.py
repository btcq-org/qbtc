#!/usr/bin/env python3
"""Helpers for scripts/vetest/run.sh (Python 3.8+, stdlib only).

    vetest_lib.py bech32-p2wpkh HASH160_HEX
    vetest_lib.py genesis-patch --net DIR [--enable-height N] [--utxo-file F] [--vk-file F]
    vetest_lib.py claim-msg --proof F --claimer A --receiver A --txid T --vout N --out F
    vetest_lib.py tallies  --logs DIR [filters/predicates, see --help]
    vetest_lib.py processed --logs DIR [--after H --upto H --truth URL --min-count N]
    vetest_lib.py rejects  --logs DIR --nodes 1,2,3 --min N
    vetest_lib.py sizes    --logs DIR
    vetest_lib.py blocktime --rpc URL --from A --to B
    vetest_lib.py jget FILE_OR_- PATH [DEFAULT]

Assertion subcommands print what they found and exit 1 when the assertion fails.
Log files are node_<i>.log (ANSI codes already stripped or not: both work).
"""
import argparse
import glob
import json
import os
import re
import sys
import urllib.request
from fractions import Fraction

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
KV = re.compile(r'([A-Za-z_][\w.]*)=("(?:[^"\\]|\\.)*"|\S+)')


# ------------------------------------------------------------------ bech32


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def bech32_encode(hrp, witver, program):
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    acc, bits, data = 0, 0, [witver]
    for byte in program:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data
    const = 1  # bech32 (BIP173), witness version 0
    pm = _polymod(values + [0] * 6) ^ const
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(charset[d] for d in data + checksum)


# ------------------------------------------------------------------- small


def strip(line):
    return ANSI.sub("", line)


def parse_line(line, message):
    """Returns the key=value dict of a log line containing `message`, else None."""
    line = strip(line)
    i = line.find(message)
    if i < 0:
        return None
    kv = {}
    for k, v in KV.findall(line[i + len(message):]):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        kv[k] = v
    return kv


def node_logs(logdir):
    out = {}
    for path in sorted(glob.glob(os.path.join(logdir, "node_*.log"))):
        n = int(re.search(r"node_(\d+)\.log$", path).group(1))
        with open(path, errors="replace") as f:
            out[n] = f.read().splitlines()
    return out


def truth(url, height, cache={}):
    if height not in cache:
        with urllib.request.urlopen("%s/truth/%d" % (url.rstrip("/"), height), timeout=60) as r:
            cache[height] = r.read().decode().strip()
    return cache[height]


def frac(s):
    return Fraction(s)


def fail(msg):
    print("ASSERT FAIL: " + msg)
    sys.exit(1)


# ---------------------------------------------------------------- commands


def cmd_bech32(a):
    print(bech32_encode("bc", 0, bytes.fromhex(a.hash160)))


def cmd_genesis_patch(a):
    for gpath in sorted(glob.glob(os.path.join(a.net, "validator*", "config", "genesis.json"))):
        with open(gpath) as f:
            g = json.load(f)
        if a.enable_height is not None:
            g["consensus"]["params"].setdefault("abci", {})["vote_extensions_enable_height"] = str(a.enable_height)
        q = g["app_state"]["qbtc"]
        if a.utxo_file:
            with open(a.utxo_file) as f:
                q["utxos"] = json.load(f)
        if a.vk_file:
            import base64
            with open(a.vk_file, "rb") as f:
                q["zk_verifying_key"] = base64.b64encode(f.read()).decode()
        with open(gpath, "w") as f:
            json.dump(g, f, indent=2)
        print("patched " + gpath)


def cmd_claim_msg(a):
    with open(a.proof) as f:
        p = json.load(f)
    msg = {
        "claimer": a.claimer,
        "utxos": [{"txid": a.txid, "vout": a.vout}],
        "proof": p["proof_data"],
        "message_hash": p["message_hash"],
        "address_hash": p["address_hash"],
        "qbtc_address_hash": p["qbtc_address_hash"],
        "pub_key_hash_sha256": p["pub_key_hash_sha256"],
        "receiver": a.receiver,
        "broadcaster": a.claimer,
    }
    with open(a.out, "w") as f:
        json.dump(msg, f, indent=2)


def collect_tallies(logs):
    """height -> {hash: {"power": max power, "total": total}} merged over all nodes/attempts."""
    tallies = {}
    for n, lines in logs.items():
        for line in lines:
            kv = parse_line(line, "btc vote tally")
            if kv is None or "btc_height" not in kv:
                continue
            try:
                h, power, total = int(kv["btc_height"]), int(kv["power"]), int(kv["total"])
            except (KeyError, ValueError):
                continue
            ent = tallies.setdefault(h, {"total": total, "cands": {}})
            ent["total"] = max(ent["total"], total)
            c = ent["cands"].setdefault(kv.get("hash", "?"), {"power": 0})
            c["power"] = max(c["power"], power)
    return tallies


def cmd_tallies(a):
    logs = node_logs(a.logs)
    if not logs:
        fail("no node_*.log files in %s" % a.logs)
    tallies = collect_tallies(logs)
    heights = sorted(h for h in tallies if (a.after is None or h > a.after) and (a.upto is None or h <= a.upto))
    if a.last:
        heights = heights[-a.last:]
    print("tallied btc heights selected: %d%s" % (len(heights), " (%d..%d)" % (heights[0], heights[-1]) if heights else ""))

    def summary(h):
        ent = tallies[h]
        cs = sorted(ent["cands"].items(), key=lambda kv: -kv[1]["power"])
        return "%d: %s (total %d)" % (h, ", ".join("%s power %d" % (c[:12], v["power"]) for c, v in cs), ent["total"])

    def winner(h):
        return max(tallies[h]["cands"].items(), key=lambda kv: kv[1]["power"])

    # invariant: the candidate with the most power is the real mainnet block
    if a.truth:
        bad = [h for h in heights if winner(h)[0] != truth(a.truth, h)]
        if bad:
            fail("winning candidate is not the mainnet block at heights %s: %s" % (bad[:10], summary(bad[0])))
        print("ok: the winning candidate equals the mainnet hash at all %d heights" % len(heights))

    def pred(h):
        ent = tallies[h]
        total = ent["total"]
        wh, wv = winner(h)
        if a.power_eq is not None and Fraction(wv["power"], total) != a.power_eq:
            return False
        if a.two_candidates:
            if len(ent["cands"]) != 2:
                return False
            loser = [v for c, v in ent["cands"].items() if c != wh][0]
            if Fraction(wv["power"], total) != Fraction(3, 4) or Fraction(loser["power"], total) != Fraction(1, 4):
                return False
            if a.truth and (wh != truth(a.truth, h) or [c for c in ent["cands"] if c != wh][0] == truth(a.truth, h)):
                return False
        if a.max_power is not None and Fraction(wv["power"], total) > a.max_power:
            return False
        return True

    ok_heights = [h for h in heights if pred(h)]
    print("heights satisfying the predicate: %d/%d" % (len(ok_heights), len(heights)))
    for h in heights[-3:]:
        print("   e.g. " + summary(h))
    if a.strict:
        bad = [h for h in heights if not pred(h)]
        if bad or not heights:
            fail("predicate failed at heights %s%s" % (bad[:10], ": " + summary(bad[0]) if bad else " (no tallies)"))
    if a.min_count is not None and len(ok_heights) < a.min_count:
        fail("only %d heights satisfy the predicate, need %d" % (len(ok_heights), a.min_count))
    if a.min_run is not None:
        best = run = 0
        prev = None
        for h in heights:
            if pred(h):
                run = run + 1 if prev is not None and h == prev + 1 else 1
                best = max(best, run)
            else:
                run = 0
            prev = h
        print("longest run of consecutive satisfying heights: %d" % best)
        if best < a.min_run:
            fail("longest run is %d, need %d" % (best, a.min_run))
    print("PASS")


def cmd_processed(a):
    logs = node_logs(a.logs)
    per_node = {}
    for n, lines in logs.items():
        for line in lines:
            kv = parse_line(line, "btc block processed")
            if kv is None or "height" not in kv:
                continue
            h = int(kv["height"])
            if (a.after is not None and h <= a.after) or (a.upto is not None and h > a.upto):
                continue
            per_node.setdefault(n, {}).setdefault(h, set()).add(kv.get("hash", "?"))
    all_heights = sorted(set(h for d in per_node.values() for h in d))
    print("btc blocks processed in the window: %d%s on nodes %s" % (
        len(all_heights), " (%d..%d)" % (all_heights[0], all_heights[-1]) if all_heights else "", sorted(per_node)))
    for n, d in per_node.items():
        for h, hashes in d.items():
            if len(hashes) != 1:
                fail("node %d applied several hashes at height %d: %s" % (n, h, hashes))
    for h in all_heights:
        hs = set(next(iter(d[h])) for d in per_node.values() if h in d)
        if len(hs) != 1:
            fail("nodes applied different hashes at height %d: %s" % (h, hs))
        if a.truth and next(iter(hs)) != truth(a.truth, h):
            fail("applied hash at height %d is not the mainnet block: %s" % (h, next(iter(hs))))
    if a.truth:
        print("ok: every applied hash equals the mainnet hash")
    if a.consecutive and all_heights and all_heights != list(range(all_heights[0], all_heights[-1] + 1)):
        fail("applied heights are not consecutive")
    if len(all_heights) < (a.min_count or 0):
        fail("only %d blocks processed, need %d" % (len(all_heights), a.min_count))
    print("PASS")


def cmd_rejects(a):
    logs = node_logs(a.logs)
    total = 0
    sample = None
    for n in [int(x) for x in a.nodes.split(",")]:
        c = 0
        for line in logs.get(n, []):
            kv = parse_line(line, "rejecting proposal")
            if kv is not None:
                c += 1
                sample = sample or kv.get("error")
        print("node %d: %d 'rejecting proposal' lines" % (n, c))
        total += c
    if sample:
        print("sample error: " + str(sample)[:300])
    if total < a.min:
        fail("expected at least %d rejections, saw %d" % (a.min, total))
    print("PASS")


def cmd_sizes(a):
    logs = node_logs(a.logs)
    series = {"extension bytes": [], "inject tx bytes": [], "extended commit bytes": [], "blocks per injection": []}
    for lines in logs.values():
        for line in lines:
            kv = parse_line(line, "btc vote extension")
            if kv and "bytes" in kv and kv["bytes"].isdigit() and int(kv["bytes"]) > 0:
                series["extension bytes"].append(int(kv["bytes"]))
            kv = parse_line(line, "injecting btc blocks")
            if kv:
                for key, name in (("tx_bytes", "inject tx bytes"), ("extended_commit_bytes", "extended commit bytes"), ("count", "blocks per injection")):
                    if key in kv and kv[key].isdigit():
                        series[name].append(int(kv[key]))
    for name, vals in series.items():
        if vals:
            print("%-24s n=%d min=%d avg=%d max=%d" % (name, len(vals), min(vals), sum(vals) // len(vals), max(vals)))
        else:
            print("%-24s (no samples)" % name)


def cmd_blocktime(a):
    from datetime import datetime

    def bt(h):
        with urllib.request.urlopen("%s/block?height=%d" % (a.rpc.rstrip("/"), h), timeout=30) as r:
            t = json.load(r)["result"]["block"]["header"]["time"]
        t = t.rstrip("Z")
        if "." in t:
            base, frac_ = t.split(".")
            t = base + "." + frac_[:6]
            return datetime.strptime(t, "%Y-%m-%dT%H:%M:%S.%f")
        return datetime.strptime(t, "%Y-%m-%dT%H:%M:%S")

    span = (bt(a.to) - bt(a.frm)).total_seconds()
    print("%.2f" % (span / max(1, a.to - a.frm)))


def cmd_jget(a):
    data = json.load(sys.stdin if a.file == "-" else open(a.file))
    cur = data
    try:
        for part in a.path.split("."):
            if part == "":
                continue
            cur = cur[int(part)] if isinstance(cur, list) else cur[part]
    except (KeyError, IndexError, ValueError, TypeError):
        if a.default is not None:
            print(a.default)
            return
        sys.exit(1)
    print(cur if not isinstance(cur, (dict, list)) else json.dumps(cur))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("bech32-p2wpkh")
    p.add_argument("hash160")
    p.set_defaults(fn=cmd_bech32)

    p = sub.add_parser("genesis-patch")
    p.add_argument("--net", required=True)
    p.add_argument("--enable-height", type=int)
    p.add_argument("--utxo-file")
    p.add_argument("--vk-file")
    p.set_defaults(fn=cmd_genesis_patch)

    p = sub.add_parser("claim-msg")
    p.add_argument("--proof", required=True)
    p.add_argument("--claimer", required=True)
    p.add_argument("--receiver", required=True)
    p.add_argument("--txid", required=True)
    p.add_argument("--vout", type=int, default=0)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_claim_msg)

    p = sub.add_parser("tallies")
    p.add_argument("--logs", required=True)
    p.add_argument("--after", type=int, help="only btc heights > this")
    p.add_argument("--upto", type=int, help="only btc heights <= this")
    p.add_argument("--last", type=int, help="only the highest K selected heights")
    p.add_argument("--truth", help="proxy control URL; the winning candidate must equal the mainnet hash")
    p.add_argument("--power-eq", type=frac, help="predicate: winner power / total == this fraction (e.g. 1, 3/4)")
    p.add_argument("--max-power", type=frac, help="predicate: winner power / total <= this fraction")
    p.add_argument("--two-candidates", action="store_true", help="predicate: exactly two candidates, 3/4 (mainnet) vs 1/4 (other)")
    p.add_argument("--strict", action="store_true", help="every selected height must satisfy the predicate")
    p.add_argument("--min-count", type=int, help="at least N heights satisfy the predicate")
    p.add_argument("--min-run", type=int, help="N consecutive heights satisfy the predicate")
    p.set_defaults(fn=cmd_tallies)

    p = sub.add_parser("processed")
    p.add_argument("--logs", required=True)
    p.add_argument("--after", type=int)
    p.add_argument("--upto", type=int)
    p.add_argument("--truth")
    p.add_argument("--min-count", type=int)
    p.add_argument("--consecutive", action="store_true")
    p.set_defaults(fn=cmd_processed)

    p = sub.add_parser("rejects")
    p.add_argument("--logs", required=True)
    p.add_argument("--nodes", required=True)
    p.add_argument("--min", type=int, default=1)
    p.set_defaults(fn=cmd_rejects)

    p = sub.add_parser("sizes")
    p.add_argument("--logs", required=True)
    p.set_defaults(fn=cmd_sizes)

    p = sub.add_parser("blocktime")
    p.add_argument("--rpc", required=True)
    p.add_argument("--from", dest="frm", type=int, required=True)
    p.add_argument("--to", type=int, required=True)
    p.set_defaults(fn=cmd_blocktime)

    p = sub.add_parser("jget")
    p.add_argument("file")
    p.add_argument("path")
    p.add_argument("default", nargs="?")
    p.set_defaults(fn=cmd_jget)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
