#!/usr/bin/env python3
"""Bitcoin JSON-RPC proxy for the qbtc vote-extension scenario harness.

Presents a bitcoind-like JSON-RPC interface (the subset qbtcd's reader and the
`qbtcd multi-node` generator use) backed by Bitcoin MAINNET data, fetched once
from a public Esplora API (default mempool.space) or from a real bitcoind and
cached on disk. Every validator gets its own listening port, so the proxy can
inject per-validator faults:

    POST /mode {"validator": 3, "mode": "ok|down|fork|frozen", "from_height": N}

Environment:
    UPSTREAM          esplora:https://mempool.space/api (default) or
                      rpc:http://user:pass@host:port
    CACHE_DIR         disk cache for blocks/headers/hashes (default ./cache)
    TIP_OFFSET        pretend the chain tip is this many blocks lower (default 0)
    BIND              listen address (default 0.0.0.0)
    BASE_PORT         validator i is served on BASE_PORT+i (default 18440)
    NUM_VALIDATORS    default 4
    TOOL_PORT         port for tools such as the generator (default 18449); never faulted
    CONTROL_PORT      control endpoint (default 18450)
    UPSTREAM_CONCURRENCY  parallel upstream requests (default 3)

Control endpoint (CONTROL_PORT):
    POST /mode {"validator": 3|"all", "mode": "...", "from_height": N}
    POST /reset                       all validators back to ok
    POST /release {"height": H}       never serve a tip above H (also {"add": n}, {"clear": true});
                                      the harness uses it to hand out blocks in controlled batches
    GET  /mode                        current modes
    POST /prefetch {"from": A, "to": B}  download blocks A..B into the cache (background)
    GET  /prefetch                    prefetch progress
    GET  /truth/<height>              the real mainnet hash at <height>
    GET  /tip                         real tip and tip served after TIP_OFFSET
    GET  /stats                       request counters

Modes (per validator):
    ok      pass-through
    down    every RPC call fails with HTTP 503
    frozen  the tip stays at the height it had when the mode was set
    fork    for heights >= from_height, getblockhash(h) returns the hash of the
            real block h-1; that block is internally consistent, so a validator
            attests a different (but self-consistent) block at h

Run `python3 btc_proxy.py --selftest` to check upstream access and the parser.
"""
import base64
import hashlib
import http.client
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FALLBACK_ESPLORA = "https://blockstream.info/api"
USER_AGENT = "qbtc-vetest-proxy/1.0"

# bitcoind RPC error codes
RPC_INVALID_PARAMETER = -8
RPC_MISC_ERROR = -1
RPC_METHOD_NOT_FOUND = -32601
RPC_INVALID_ADDRESS_OR_KEY = -5


def log(msg):
    sys.stderr.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stderr.flush()


class RpcError(Exception):
    def __init__(self, code, message, http_status=500):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.http_status = http_status


class UpstreamNotFound(Exception):
    pass


class UpstreamError(Exception):
    pass


class TooSlow(Exception):
    pass


# ---------------------------------------------------------------- upstreams


class Upstream(object):
    """Fetches mainnet data. Methods raise UpstreamNotFound / UpstreamError."""

    def tip_height(self):
        raise NotImplementedError

    def hash_at(self, height):
        raise NotImplementedError

    def raw_block(self, block_hash):
        raise NotImplementedError

    def raw_header(self, block_hash):
        raise NotImplementedError

    def height_of(self, block_hash):
        raise NotImplementedError


class EsploraUpstream(Upstream):
    """Esplora REST API. Several base URLs are tried in order; an endpoint that
    errors out or downloads too slowly is demoted for PENALTY seconds (public
    instances throttle big raw-block downloads to a few KB/s)."""

    PENALTY = 600.0
    MIN_RATE = 150 * 1024   # bytes/s below which a large download counts as too slow
    GRACE = 8.0             # seconds before the rate is judged

    def __init__(self, urls, concurrency=3):
        self.urls = [u.rstrip("/") for u in urls]
        self.penalty_until = {u: 0.0 for u in self.urls}
        self.sem = threading.Semaphore(concurrency)
        self.requests = 0
        self.retries = 0

    def _order(self):
        now = time.time()
        return sorted(self.urls, key=lambda u: (self.penalty_until[u] > now, self.urls.index(u)))

    def _read(self, resp):
        chunks, n, t0 = [], 0, time.time()
        while True:
            c = resp.read(65536)
            if not c:
                break
            chunks.append(c)
            n += len(c)
            el = time.time() - t0
            if el > self.GRACE and n / el < self.MIN_RATE:
                raise TooSlow("%.0f KB/s after %.0fs" % (n / el / 1024, el))
        return b"".join(chunks)

    def _get_one(self, base, path, attempts):
        delay = 1.0
        last = None
        for attempt in range(attempts):
            req = urllib.request.Request(base + path, headers={"User-Agent": USER_AGENT})
            try:
                with self.sem:
                    self.requests += 1
                    with urllib.request.urlopen(req, timeout=20) as resp:
                        return self._read(resp)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    raise UpstreamNotFound(path)
                last = "HTTP %d" % e.code
                if e.code == 429 or e.code >= 500:
                    ra = e.headers.get("Retry-After") if e.headers else None
                    wait = delay
                    if ra and ra.isdigit():
                        wait = max(wait, min(float(ra), 30))
                    self.retries += 1
                    time.sleep(wait)
                    delay = min(delay * 2, 20)
                    continue
                raise UpstreamError("%s%s: %s" % (base, path, last))
            except TooSlow as e:
                raise UpstreamError("%s%s: too slow (%s)" % (base, path, e))
            except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
                last = str(e)
                self.retries += 1
                time.sleep(delay)
                delay = min(delay * 2, 20)
        raise UpstreamError("%s%s: gave up (%s)" % (base, path, last))

    def _get(self, path):
        last = None
        order = self._order()
        for i, base in enumerate(order):
            try:
                # the last endpoint gets more patience
                return self._get_one(base, path, 5 if i == len(order) - 1 else 3)
            except UpstreamError as e:
                last = e
                self.penalty_until[base] = time.time() + self.PENALTY
                log("upstream %s demoted for %ds (%s)" % (base, self.PENALTY, e))
        raise last or UpstreamError("no upstream")

    def tip_height(self):
        return int(self._get("/blocks/tip/height").decode().strip())

    def hash_at(self, height):
        return self._get("/block-height/%d" % height).decode().strip()

    def raw_block(self, block_hash):
        return self._get("/block/%s/raw" % block_hash)

    def raw_header(self, block_hash):
        return bytes.fromhex(self._get("/block/%s/header" % block_hash).decode().strip())

    def height_of(self, block_hash):
        return int(json.loads(self._get("/block/%s/status" % block_hash).decode())["height"])


class RpcUpstream(Upstream):
    def __init__(self, url):
        from urllib.parse import urlparse
        u = urlparse(url)
        self.endpoint = "%s://%s:%s" % (u.scheme, u.hostname, u.port or 8332)
        self.auth = base64.b64encode(("%s:%s" % (u.username or "", u.password or "")).encode()).decode()
        self.requests = 0
        self.retries = 0
        self.lock = threading.Lock()

    def _call(self, method, params):
        body = json.dumps({"jsonrpc": "1.0", "id": "p", "method": method, "params": params}).encode()
        delay = 1.0
        for attempt in range(5):
            req = urllib.request.Request(self.endpoint, data=body, headers={
                "Authorization": "Basic " + self.auth, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    d = json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                try:
                    d = json.loads(e.read().decode())
                except Exception:
                    d = None
                if d is None or not d.get("error"):
                    self.retries += 1
                    time.sleep(delay)
                    delay = min(delay * 2, 20)
                    continue
            except (urllib.error.URLError, OSError, http.client.HTTPException):
                self.retries += 1
                time.sleep(delay)
                delay = min(delay * 2, 20)
                continue
            self.requests += 1
            if d.get("error"):
                if d["error"].get("code") in (RPC_INVALID_PARAMETER, RPC_INVALID_ADDRESS_OR_KEY):
                    raise UpstreamNotFound(d["error"].get("message", ""))
                raise UpstreamError(d["error"].get("message", "rpc error"))
            return d["result"]
        raise UpstreamError("rpc %s: gave up" % method)

    def tip_height(self):
        return int(self._call("getblockcount", []))

    def hash_at(self, height):
        return self._call("getblockhash", [height])

    def raw_block(self, block_hash):
        return bytes.fromhex(self._call("getblock", [block_hash, 0]))

    def raw_header(self, block_hash):
        return bytes.fromhex(self._call("getblockheader", [block_hash, False]))

    def height_of(self, block_hash):
        return int(self._call("getblockheader", [block_hash, True])["height"])


def make_upstream(spec, concurrency):
    if spec.startswith("esplora:"):
        urls = [u for u in spec[len("esplora:"):].split(",") if u]  # comma separated list allowed
        if FALLBACK_ESPLORA not in urls:
            urls.append(FALLBACK_ESPLORA)
        return EsploraUpstream(urls, concurrency)
    if spec.startswith("rpc:"):
        return RpcUpstream(spec[len("rpc:"):])
    raise SystemExit("UPSTREAM must start with esplora: or rpc:")


# -------------------------------------------------------------------- store


class Store(object):
    """Caches upstream data in memory and on disk; each item is fetched once."""

    TIP_TTL = 5.0
    NEAR_TIP_TTL = 20.0
    STABLE_DEPTH = 8  # hashes this deep below the tip are cached forever

    def __init__(self, upstream, cache_dir, tip_offset=0):
        self.up = upstream
        self.dir = cache_dir
        self.tip_offset = tip_offset
        self.release_cap = None  # POST /release: never serve a tip above this height
        os.makedirs(os.path.join(cache_dir, "blocks"), exist_ok=True)
        os.makedirs(os.path.join(cache_dir, "headers"), exist_ok=True)
        os.makedirs(os.path.join(cache_dir, "hashes"), exist_ok=True)
        self.lock = threading.Lock()
        self.key_locks = {}
        self._tip = None
        self._tip_at = 0.0
        self.hashes = {}      # height -> (hash, fetched_at, stable)
        self.heights = {}     # hash -> height
        self.blocks = OrderedDict()  # hash -> raw bytes (small LRU)
        self.upstream_blocks = 0

    def _key_lock(self, key):
        with self.lock:
            lk = self.key_locks.get(key)
            if lk is None:
                lk = self.key_locks[key] = threading.Lock()
            return lk

    # tip
    def real_tip(self):
        now = time.time()
        with self.lock:
            if self._tip is not None and now - self._tip_at < self.TIP_TTL:
                return self._tip
        with self._key_lock("tip"):
            with self.lock:
                if self._tip is not None and time.time() - self._tip_at < self.TIP_TTL:
                    return self._tip
            try:
                tip = self.up.tip_height()
            except UpstreamError:
                with self.lock:
                    if self._tip is not None:  # serve the stale tip rather than fail
                        return self._tip
                raise
            with self.lock:
                self._tip, self._tip_at = tip, time.time()
            return tip

    def served_tip(self):
        tip = max(0, self.real_tip() - self.tip_offset)
        if self.release_cap is not None:
            tip = min(tip, self.release_cap)
        return tip

    # hash by height (truth)
    def truth_hash(self, height):
        if height < 0:
            raise UpstreamNotFound(str(height))
        with self.lock:
            ent = self.hashes.get(height)
        if ent and (ent[2] or time.time() - ent[1] < self.NEAR_TIP_TTL):
            return ent[0]
        path = os.path.join(self.dir, "hashes", str(height))
        if os.path.exists(path):
            with open(path) as f:
                h = f.read().strip()
            self._remember(height, h, True)
            return h
        with self._key_lock("h%d" % height):
            tip = self.real_tip()
            h = self.up.hash_at(height)
            stable = height <= tip - self.STABLE_DEPTH
            if stable:
                tmp = path + ".tmp%d" % threading.get_ident()
                with open(tmp, "w") as f:
                    f.write(h)
                os.replace(tmp, path)
            self._remember(height, h, stable)
            return h

    def _remember(self, height, h, stable):
        with self.lock:
            self.hashes[height] = (h, time.time(), stable)
            self.heights[h] = height

    def height_of(self, block_hash):
        with self.lock:
            h = self.heights.get(block_hash)
        if h is not None:
            return h
        h = self.up.height_of(block_hash)
        with self.lock:
            self.heights[block_hash] = h
        return h

    # blocks
    def raw_block(self, block_hash):
        with self.lock:
            b = self.blocks.get(block_hash)
            if b is not None:
                self.blocks.move_to_end(block_hash)
                return b
        path = os.path.join(self.dir, "blocks", block_hash + ".bin")
        if not os.path.exists(path):
            with self._key_lock("b" + block_hash):
                if not os.path.exists(path):
                    t0 = time.time()
                    raw = self.up.raw_block(block_hash)
                    if len(raw) < 81 or block_hash_of(raw[:80]) != block_hash:
                        raise UpstreamError("upstream returned a block that does not hash to %s" % block_hash)
                    tmp = path + ".tmp%d" % threading.get_ident()
                    with open(tmp, "wb") as f:
                        f.write(raw)
                    os.replace(tmp, path)
                    self.upstream_blocks += 1
                    log("fetched block %s (%.1f MB) in %.1fs" % (block_hash[:16], len(raw) / 1e6, time.time() - t0))
        with open(path, "rb") as f:
            raw = f.read()
        with self.lock:
            self.blocks[block_hash] = raw
            while len(self.blocks) > 24:
                self.blocks.popitem(last=False)
        return raw

    def raw_header(self, block_hash):
        path = os.path.join(self.dir, "headers", block_hash + ".bin")
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        bpath = os.path.join(self.dir, "blocks", block_hash + ".bin")
        if os.path.exists(bpath):
            with open(bpath, "rb") as f:
                hdr = f.read(80)
        else:
            with self._key_lock("hd" + block_hash):
                hdr = self.up.raw_header(block_hash)
        if len(hdr) != 80 or block_hash_of(hdr) != block_hash:
            raise UpstreamError("bad header for %s" % block_hash)
        tmp = path + ".tmp%d" % threading.get_ident()
        with open(tmp, "wb") as f:
            f.write(hdr)
        os.replace(tmp, path)
        return hdr


# ------------------------------------------------------------ block parsing


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def block_hash_of(header80):
    return dsha(header80)[::-1].hex()


def read_varint(b, o):
    v = b[o]
    if v < 0xFD:
        return v, o + 1
    if v == 0xFD:
        return int.from_bytes(b[o + 1:o + 3], "little"), o + 3
    if v == 0xFE:
        return int.from_bytes(b[o + 1:o + 5], "little"), o + 5
    return int.from_bytes(b[o + 1:o + 9], "little"), o + 9


def parse_txids(raw):
    """Returns (header80, [txid bytes in internal order]) from a raw block."""
    header = raw[:80]
    n, o = read_varint(raw, 80)
    txids = []
    for _ in range(n):
        start = o
        o += 4  # version
        segwit = raw[o] == 0x00 and raw[o + 1] != 0x00
        if segwit:
            o += 2
        nin, o = read_varint(raw, o)
        for _ in range(nin):
            o += 36
            sl, o = read_varint(raw, o)
            o += sl + 4
        nout, o = read_varint(raw, o)
        for _ in range(nout):
            o += 8
            sl, o = read_varint(raw, o)
            o += sl
        body_end = o
        if segwit:
            for _ in range(nin):
                items, o = read_varint(raw, o)
                for _ in range(items):
                    il, o = read_varint(raw, o)
                    o += il
        o += 4  # locktime
        if segwit:
            # txid hashes version | inputs | outputs | locktime
            ins_outs_start = start + 6
            txid = dsha(raw[start:start + 4] + raw[ins_outs_start:body_end] + raw[o - 4:o])
        else:
            txid = dsha(raw[start:o])
        txids.append(txid)
    return header, txids


def merkle_root(txids):
    layer = list(txids)
    if not layer:
        return b"\x00" * 32
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [dsha(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def check_block(raw):
    header, txids = parse_txids(raw)
    return merkle_root(txids) == header[36:68], len(txids)


# ------------------------------------------------------------------- faults


class Modes(object):
    def __init__(self, n):
        self.lock = threading.Lock()
        self.n = n
        self.state = {i: {"mode": "ok", "from_height": 0, "frozen_tip": None} for i in range(n)}
        self.counters = {i: 0 for i in list(range(n)) + ["tool"]}

    def get(self, v):
        with self.lock:
            return dict(self.state[v]) if v in self.state else {"mode": "ok", "from_height": 0, "frozen_tip": None}

    def set(self, v, mode, from_height, store):
        if mode not in ("ok", "down", "fork", "frozen"):
            raise ValueError("unknown mode %r" % mode)
        targets = list(range(self.n)) if v == "all" else [int(v)]
        tip = store.served_tip() if mode == "frozen" else None
        with self.lock:
            for t in targets:
                if t not in self.state:
                    raise ValueError("unknown validator %r" % t)
                self.state[t] = {"mode": mode, "from_height": int(from_height), "frozen_tip": tip}
        log("mode: validators %s -> %s (from_height=%s, frozen_tip=%s)" % (targets, mode, from_height, tip))

    def snapshot(self):
        with self.lock:
            return {str(k): dict(v) for k, v in self.state.items()}


class Prefetcher(object):
    """Downloads a range of blocks into the cache in the background, so the
    scenarios do not depend on upstream speed."""

    def __init__(self, store, workers=3):
        self.store = store
        self.workers = workers
        self.lock = threading.Lock()
        self.status = {"running": False, "total": 0, "done": 0, "failed": 0, "from": 0, "to": 0}

    def start(self, lo, hi):
        with self.lock:
            if self.status["running"]:
                raise ValueError("prefetch already running")
            self.status = {"running": True, "total": hi - lo + 1, "done": 0, "failed": 0, "from": lo, "to": hi}
        heights = list(range(lo, hi + 1))
        q_lock = threading.Lock()

        def worker():
            while True:
                with q_lock:
                    if not heights:
                        break
                    h = heights.pop(0)
                ok = False
                for _ in range(3):
                    try:
                        self.store.raw_block(self.store.truth_hash(h))
                        ok = True
                        break
                    except (UpstreamError, UpstreamNotFound) as e:
                        log("prefetch %d: %s" % (h, e))
                        time.sleep(2)
                with self.lock:
                    self.status["done" if ok else "failed"] += 1

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(self.workers)]

        def finisher():
            for t in threads:
                t.join()
            with self.lock:
                self.status["running"] = False
            log("prefetch finished: %s" % self.status)

        for t in threads:
            t.start()
        threading.Thread(target=finisher, daemon=True).start()

    def get(self):
        with self.lock:
            return dict(self.status)


# ---------------------------------------------------------------- rpc logic


class Backend(object):
    def __init__(self, store, modes):
        self.store = store
        self.modes = modes

    def tip(self, v):
        m = self.modes.get(v)
        if m["mode"] == "frozen" and m["frozen_tip"] is not None:
            return m["frozen_tip"]
        return self.store.served_tip()

    def hash_at(self, v, height):
        m = self.modes.get(v)
        tip = self.tip(v)
        if height < 0 or height > tip:
            raise RpcError(RPC_INVALID_PARAMETER, "Block height out of range")
        if m["mode"] == "fork" and height >= m["from_height"] and height >= 1:
            height -= 1
        try:
            return self.store.truth_hash(height)
        except UpstreamNotFound:
            raise RpcError(RPC_INVALID_PARAMETER, "Block height out of range")

    def _check_hash(self, h):
        if not isinstance(h, str) or len(h) != 64 or any(c not in "0123456789abcdef" for c in h.lower()):
            raise RpcError(RPC_INVALID_PARAMETER, "blockhash must be of length 64 (not %d)" % (len(h) if isinstance(h, str) else 0))
        return h.lower()

    def call(self, v, method, params):
        if isinstance(params, dict):
            raise RpcError(RPC_INVALID_PARAMETER, "named params unsupported")
        params = params or []
        s = self.store
        if method == "getblockcount":
            return self.tip(v)
        if method == "getbestblockhash":
            return self.hash_at(v, self.tip(v))
        if method == "getblockhash":
            return self.hash_at(v, int(params[0]))
        if method == "getblock":
            h = self._check_hash(params[0])
            verbosity = params[1] if len(params) > 1 else 1
            if verbosity is True:
                verbosity = 1
            if verbosity is False:
                verbosity = 0
            try:
                raw = s.raw_block(h)
            except UpstreamNotFound:
                raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")
            if verbosity == 0:
                return raw.hex()
            if verbosity == 1:
                _, txids = parse_txids(raw)
                d = self._header_json(v, h, raw[:80])
                d["size"] = len(raw)
                d["nTx"] = len(txids)
                d["tx"] = [t[::-1].hex() for t in txids]
                return d
            raise RpcError(RPC_INVALID_PARAMETER, "getblock verbosity 2 is not supported by this proxy")
        if method == "getblockheader":
            h = self._check_hash(params[0])
            verbose = params[1] if len(params) > 1 else True
            try:
                hdr = s.raw_header(h)
            except UpstreamNotFound:
                raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")
            if verbose is False or verbose == 0:
                return hdr.hex()
            return self._header_json(v, h, hdr)
        if method == "getblockchaininfo":
            tip = self.tip(v)
            return {"chain": "main", "blocks": tip, "headers": tip,
                    "bestblockhash": self.hash_at(v, tip), "difficulty": 1.0, "time": int(time.time()),
                    "mediantime": int(time.time()), "verificationprogress": 1.0,
                    "initialblockdownload": False, "chainwork": "00", "size_on_disk": 0,
                    "pruned": False, "warnings": ""}
        if method == "getnetworkinfo":
            return {"version": 280000, "subversion": "/qbtc-vetest-proxy:1.0/", "protocolversion": 70016,
                    "connections": 8, "networkactive": True}
        if method == "ping":
            return None
        raise RpcError(RPC_METHOD_NOT_FOUND, "Method not found", http_status=404)

    def _header_json(self, v, h, hdr):
        tip = self.tip(v)
        try:
            height = self.store.height_of(h)
        except (UpstreamNotFound, UpstreamError):
            height = None
        d = {"hash": h, "version": int.from_bytes(hdr[0:4], "little"),
             "versionHex": "%08x" % int.from_bytes(hdr[0:4], "little"),
             "merkleroot": hdr[36:68][::-1].hex(), "time": int.from_bytes(hdr[68:72], "little"),
             "mediantime": int.from_bytes(hdr[68:72], "little"),
             "nonce": int.from_bytes(hdr[76:80], "little"), "bits": hdr[72:76][::-1].hex(),
             "difficulty": 1.0, "chainwork": "00",
             "previousblockhash": hdr[4:36][::-1].hex()}
        if height is not None:
            d["height"] = height
            d["confirmations"] = max(1, tip - height + 1)
            if height < tip:
                try:
                    d["nextblockhash"] = self.hash_at(v, height + 1)
                except RpcError:
                    pass
        return d


# ------------------------------------------------------------------- server


def make_rpc_handler(backend, validator):
    class RpcHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def _send(self, status, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            key = validator if validator is not None else "tool"
            with backend.modes.lock:
                backend.modes.counters[key] = backend.modes.counters.get(key, 0) + 1
            if validator is not None and backend.modes.get(validator)["mode"] == "down":
                self._send(503, "Service Unavailable (vetest: down)", "text/plain")
                return
            try:
                req = json.loads(body.decode())
            except Exception:
                self._send(400, "bad json", "text/plain")
                return
            batch = isinstance(req, list)
            reqs = req if batch else [req]
            out = []
            status = 200
            for r in reqs:
                rid = r.get("id")
                try:
                    res = backend.call(validator, r.get("method"), r.get("params"))
                    out.append({"jsonrpc": "2.0", "result": res, "error": None, "id": rid})
                except RpcError as e:
                    status = e.http_status if not batch else 200
                    out.append({"jsonrpc": "2.0", "result": None, "error": {"code": e.code, "message": e.message}, "id": rid})
                except (UpstreamError, UpstreamNotFound) as e:
                    status = 500 if not batch else 200
                    out.append({"jsonrpc": "2.0", "result": None, "error": {"code": RPC_MISC_ERROR, "message": "upstream: %s" % e}, "id": rid})
                except (IndexError, ValueError, TypeError) as e:
                    status = 500 if not batch else 200
                    out.append({"jsonrpc": "2.0", "result": None, "error": {"code": RPC_INVALID_PARAMETER, "message": "bad params: %s" % e}, "id": rid})
            try:
                self._send(status, json.dumps(out if batch else out[0]))
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            self._send(200, "qbtc vetest btc proxy (validator %s)\n" % validator, "text/plain")

    return RpcHandler


def make_control_handler(backend, upstream, prefetcher):
    class ControlHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def _send(self, status, obj):
            data = (obj if isinstance(obj, str) else json.dumps(obj)).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json" if not isinstance(obj, str) else "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            p = self.path.rstrip("/")
            try:
                if p.startswith("/truth/"):
                    self._send(200, backend.store.truth_hash(int(p[len("/truth/"):])) + "\n")
                elif p == "/mode":
                    self._send(200, backend.modes.snapshot())
                elif p == "/prefetch":
                    self._send(200, prefetcher.get())
                elif p == "/tip":
                    self._send(200, {"real_tip": backend.store.real_tip(), "served_tip": backend.store.served_tip(),
                                     "release_cap": backend.store.release_cap, "tip_offset": backend.store.tip_offset})
                elif p == "/stats":
                    self._send(200, {"calls": {str(k): v for k, v in backend.modes.counters.items()},
                                     "upstream_requests": upstream.requests, "upstream_retries": upstream.retries,
                                     "blocks_fetched": backend.store.upstream_blocks})
                else:
                    self._send(404, {"error": "not found"})
            except (UpstreamNotFound, UpstreamError, ValueError) as e:
                self._send(500, {"error": str(e)})

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b"{}"
            p = self.path.rstrip("/")
            try:
                if p == "/mode":
                    d = json.loads(body.decode() or "{}")
                    backend.modes.set(d["validator"], d["mode"], d.get("from_height", 0), backend.store)
                    self._send(200, backend.modes.snapshot())
                elif p == "/reset":
                    backend.modes.set("all", "ok", 0, backend.store)
                    self._send(200, backend.modes.snapshot())
                elif p == "/release":
                    d = json.loads(body.decode() or "{}")
                    st = backend.store
                    if "height" in d:
                        st.release_cap = int(d["height"])
                    elif "add" in d:
                        st.release_cap = (st.served_tip() if st.release_cap is None else st.release_cap) + int(d["add"])
                    elif d.get("clear"):
                        st.release_cap = None
                    else:
                        raise ValueError('need "height", "add" or "clear"')
                    log("release cap -> %s (served tip %d)" % (st.release_cap, st.served_tip()))
                    self._send(200, {"release_cap": st.release_cap, "served_tip": st.served_tip()})
                elif p == "/prefetch":
                    d = json.loads(body.decode() or "{}")
                    prefetcher.start(int(d["from"]), int(d["to"]))
                    self._send(200, prefetcher.get())
                else:
                    self._send(404, {"error": "not found"})
            except (KeyError, ValueError) as e:
                self._send(400, {"error": str(e)})

    return ControlHandler


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def handle_error(self, request, client_address):
        pass


def start_servers(backend, upstream, bind, base_port, n, tool_port, control_port):
    servers = []
    for i in range(n):
        servers.append(QuietServer((bind, base_port + i), make_rpc_handler(backend, i)))
    servers.append(QuietServer((bind, tool_port), make_rpc_handler(backend, None)))
    servers.append(QuietServer((bind, control_port), make_control_handler(backend, upstream, Prefetcher(backend.store))))
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return servers


# ----------------------------------------------------------------- selftest


def rpc(port, method, params=None, path_user="u:p"):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    req = urllib.request.Request("http://127.0.0.1:%d/" % port, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, None


def control(port, method, path, obj=None):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=data, method=method)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def selftest(spec, concurrency):
    import tempfile
    failures = []

    def check(name, cond, detail=""):
        print("%-4s %s %s" % ("ok" if cond else "FAIL", name, detail))
        if not cond:
            failures.append(name)

    up = make_upstream(spec, concurrency)
    cache = tempfile.mkdtemp(prefix="vetest-proxy-selftest-")
    store = Store(up, cache)
    tip = store.real_tip()
    print("upstream tip height:", tip)
    height = tip - 10
    h = store.truth_hash(height)
    raw = store.raw_block(h)
    ok, ntx = check_block(raw)
    check("raw block parses, merkle root matches header", ok, "(height %d, %d txs, %.2f MB)" % (height, ntx, len(raw) / 1e6))
    check("block hash matches", block_hash_of(raw[:80]) == h)

    modes = Modes(4)
    backend = Backend(store, modes)
    servers = start_servers(backend, up, "127.0.0.1", 28440, 4, 28449, 28450)
    try:
        st, r = rpc(28440, "getblockcount")
        check("getblockcount", st == 200 and r["result"] == tip, str(r))
        st, r = rpc(28440, "getblockhash", [height])
        check("getblockhash", r["result"] == h)
        st, r = rpc(28440, "getblock", [h, 0])
        check("getblock raw hex", r["result"] == raw.hex())
        st, r = rpc(28440, "getblockheader", [h, False])
        check("getblockheader raw", r["result"] == raw[:80].hex())
        st, r = rpc(28440, "getblockheader", [h, True])
        check("getblockheader verbose", r["result"].get("height") == height and r["result"]["hash"] == h, str(r["result"].get("height")))
        st, r = rpc(28449, "getblockchaininfo")
        check("getblockchaininfo on tool port", r["result"]["blocks"] == tip and r["result"]["chain"] == "main")
        st, r = rpc(28440, "getblockhash", [tip + 1000])
        check("out of range -> rpc error -8", st == 500 and r["error"]["code"] == -8)
        # faults
        control(28450, "POST", "/mode", {"validator": 3, "mode": "down"})
        st, _ = rpc(28443, "getblockcount")
        st0, _ = rpc(28440, "getblockcount")
        check("down mode: v3 fails, v0 ok", st == 503 and st0 == 200)
        control(28450, "POST", "/mode", {"validator": 3, "mode": "fork", "from_height": height})
        st, r = rpc(28443, "getblockhash", [height])
        prev = store.truth_hash(height - 1)
        check("fork mode: height serves block of height-1", r["result"] == prev)
        st, r = rpc(28443, "getblockhash", [height - 1])
        check("fork mode: below from_height unchanged", r["result"] == prev)
        st, r = rpc(28443, "getblock", [prev, 0])
        okf, _ = check_block(bytes.fromhex(r["result"]))
        check("fork mode: served block is internally consistent", okf)
        control(28450, "POST", "/release", {"height": tip - 20})
        st, r = rpc(28440, "getblockcount")
        check("release cap limits the served tip", r["result"] == tip - 20)
        control(28450, "POST", "/mode", {"validator": 2, "mode": "frozen"})
        control(28450, "POST", "/release", {"height": tip - 30})
        st, r = rpc(28442, "getblockcount")
        check("frozen validator keeps its tip", r["result"] == tip - 20)
        control(28450, "POST", "/release", {"clear": True})
        control(28450, "POST", "/reset")
        check("truth endpoint", control(28450, "GET", "/truth/%d" % height).strip() == h)
        control(28450, "POST", "/prefetch", {"from": height, "to": height})
        for _ in range(100):
            st = json.loads(control(28450, "GET", "/prefetch"))
            if not st["running"]:
                break
            time.sleep(0.2)
        check("prefetch", st["done"] == 1 and st["failed"] == 0, str(st))
    finally:
        for s in servers:
            s.shutdown()
    print("\nselftest %s" % ("FAILED: " + ", ".join(failures) if failures else "passed"))
    return 1 if failures else 0


def main():
    spec = os.environ.get("UPSTREAM", "esplora:https://mempool.space/api")
    conc = int(os.environ.get("UPSTREAM_CONCURRENCY", "3"))
    if "--selftest" in sys.argv:
        sys.exit(selftest(spec, conc))
    n = int(os.environ.get("NUM_VALIDATORS", "4"))
    base = int(os.environ.get("BASE_PORT", "18440"))
    tool = int(os.environ.get("TOOL_PORT", "18449"))
    ctl = int(os.environ.get("CONTROL_PORT", "18450"))
    bind = os.environ.get("BIND", "0.0.0.0")
    cache = os.environ.get("CACHE_DIR", os.path.join(os.getcwd(), "cache"))
    offset = int(os.environ.get("TIP_OFFSET", "0"))
    up = make_upstream(spec, conc)
    store = Store(up, cache, offset)
    modes = Modes(n)
    backend = Backend(store, modes)
    start_servers(backend, up, bind, base, n, tool, ctl)
    log("btc proxy up: validators %d..%d, tools %d, control %d, upstream %s, tip_offset %d, cache %s" %
        (base, base + n - 1, tool, ctl, spec.split("@")[-1], offset, cache))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
