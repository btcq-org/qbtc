#!/usr/bin/env python3
"""Helpers for tests/vetest/run.sh (Python 3.8+, stdlib only).

    vetest_lib.py bech32-p2wpkh HASH160_HEX
    vetest_lib.py base58-p2pkh HASH160_HEX
    vetest_lib.py genesis-patch --net DIR [--enable-height N] [--utxo-file F] [--vk-file F]
    vetest_lib.py claim-msg --proof F --claimer A --receiver A --txid T --vout N --out F
    vetest_lib.py genesis-utxos --out F [--base F] SPEC...   (SPEC = txid:vout:amount_sats:address)
    vetest_lib.py key-hex FILE                               (WIF or 64 hex chars -> 32-byte hex)
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


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_decode(s):
    """Returns the payload (version byte included) of a base58check string; raises ValueError."""
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            raise ValueError("invalid base58 character %r" % c)
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        raise ValueError("too short")
    import hashlib
    body, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != chk:
        raise ValueError("bad base58 checksum")
    return body


def bech32_decode(addr):
    """Returns (hrp, witver, program) of a bech32 (v0) address; raises ValueError."""
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if addr != addr.lower() and addr != addr.upper():
        raise ValueError("mixed case")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        raise ValueError("malformed bech32")
    hrp, rest = addr[:pos], addr[pos + 1:]
    if any(c not in charset for c in rest):
        raise ValueError("invalid bech32 character")
    data = [charset.index(c) for c in rest]
    if _polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data) != 1:
        raise ValueError("bad bech32 checksum")
    data = data[:-6]
    if not data or data[0] != 0:
        raise ValueError("only witness version 0 is supported")
    acc, bits, out = 0, 0, bytearray()
    for v in data[1:]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or (acc & ((1 << bits) - 1)):
        raise ValueError("bad bech32 padding")
    return hrp, data[0], bytes(out)


def decode_mainnet_address(addr):
    """Returns (kind, hash160 hex) for a mainnet P2PKH ('1...') or P2WPKH ('bc1q...') address."""
    if addr.lower().startswith("bc1"):
        hrp, _, prog = bech32_decode(addr)
        if hrp != "bc" or len(prog) != 20:
            raise ValueError("not a mainnet P2WPKH address (witness program must be 20 bytes)")
        return "p2wpkh", prog.hex()
    body = b58check_decode(addr)
    if len(body) != 21 or body[0] != 0x00:
        raise ValueError("not a mainnet P2PKH address (must start with 1)")
    return "p2pkh", body[1:].hex()


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


def cmd_p2pkh(a):
    import hashlib
    body = b"\x00" + bytes.fromhex(a.hash160)
    raw = body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    print("1" * (len(raw) - len(raw.lstrip(b"\0"))) + out)


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


def cmd_genesis_utxos(a):
    utxos = []
    if a.base:
        with open(a.base) as f:
            utxos = json.load(f)
    seen = set((u["txid"], int(u["vout"])) for u in utxos)
    for spec in a.specs:
        parts = spec.split(":", 3)
        if len(parts) != 4:
            sys.exit("bad --genesis-utxo %r: expected <txid>:<vout>:<amount_sats>:<address>" % spec)
        txid, vout, amount, addr = parts
        if not re.fullmatch(r"[0-9a-fA-F]{64}", txid):
            sys.exit("bad --genesis-utxo %r: txid must be 64 hex characters" % spec)
        if not vout.isdigit() or int(vout) > 0xFFFFFFFF:
            sys.exit("bad --genesis-utxo %r: vout must be a non-negative integer" % spec)
        if not amount.isdigit() or int(amount) <= 0:
            sys.exit("bad --genesis-utxo %r: amount_sats must be a positive integer" % spec)
        try:
            kind, h = decode_mainnet_address(addr)
        except ValueError as e:
            sys.exit("bad --genesis-utxo %r: address %s: %s" % (spec, addr, e))
        key = (txid.lower(), int(vout))
        if key in seen:
            sys.exit("duplicate UTXO %s:%d" % key)
        seen.add(key)
        if kind == "p2wpkh":
            spk = {"hex": "0014" + h, "type": "witness_v0_keyhash", "address": addr}
        else:
            spk = {"hex": "76a914" + h + "88ac", "type": "pubkeyhash", "address": addr}
        utxos.append({"txid": txid.lower(), "vout": int(vout), "amount": amount, "entitled_amount": amount,
                      "script_pub_key": spk, "block_height": "0"})
        print("genesis utxo %s:%s %s sats %s (%s)" % (txid.lower(), vout, amount, addr, kind), file=sys.stderr)
    with open(a.out, "w") as f:
        json.dump(utxos, f, indent=2)


def cmd_key_hex(a):
    # never echoes the key; errors mention only what is wrong with the format
    with open(a.file) as f:
        s = f.read().strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", s):
        print(s.lower())
        return
    try:
        body = b58check_decode(s)
    except ValueError as e:
        sys.exit("the key is neither 64 hex characters nor a valid WIF (%s)" % e)
    if body[0] != 0x80:
        sys.exit("the WIF is not a Bitcoin mainnet private key (version byte != 0x80)")
    if len(body) == 34 and body[33] == 0x01:
        print(body[1:33].hex())
    elif len(body) == 33:
        sys.exit("uncompressed WIF keys are not supported (the proof uses the compressed public key); import it as compressed")
    else:
        sys.exit("unexpected WIF length")


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
    if a.max_candidates is not None:
        bad = [h for h in heights if len(tallies[h]["cands"]) > a.max_candidates]
        if bad:
            fail("more than %d candidate(s) at heights %s: %s" % (a.max_candidates, bad[:10], summary(bad[0])))
        print("ok: at most %d candidate(s) at all %d heights" % (a.max_candidates, len(heights)))
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

    p = sub.add_parser("base58-p2pkh")
    p.add_argument("hash160")
    p.set_defaults(fn=cmd_p2pkh)

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

    p = sub.add_parser("genesis-utxos")
    p.add_argument("--out", required=True)
    p.add_argument("--base", help="JSON list of UTXOs to start from")
    p.add_argument("specs", nargs="+", metavar="SPEC")
    p.set_defaults(fn=cmd_genesis_utxos)

    p = sub.add_parser("key-hex")
    p.add_argument("file")
    p.set_defaults(fn=cmd_key_hex)

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
    p.add_argument("--max-candidates", type=int, help="no selected height has more than N candidates")
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
