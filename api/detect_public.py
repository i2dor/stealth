#!/usr/bin/env python3
import base58
import sys
import re
import os
import json
import time
from collections import defaultdict

import requests
from bip_utils import Bip32Secp256k1, P2WPKHAddrEncoder, CoinsConf

_primary = os.environ.get("ESPLORA_API_URL", "https://blockstream.info/api").rstrip("/")
_fallback = os.environ.get("ESPLORA_FALLBACK_URL", "https://mempool.space/api").rstrip("/")
API_BASE = _primary

REQUEST_DELAY = float(os.environ.get("REQUEST_DELAY", "0.25"))
REQUEST_DELAY_LARGE = float(os.environ.get("REQUEST_DELAY_LARGE", "0.5"))
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2.0
GAP_LIMIT = int(os.environ.get("GAP_LIMIT", "20"))
AUTO_BATCH_SIZE = int(os.environ.get("AUTO_BATCH_SIZE", "20"))
MAX_AUTO_ADDRESSES = int(os.environ.get("MAX_AUTO_ADDRESSES", "500"))

# Whirlpool known pool denominations in satoshis
WHIRLPOOL_POOL_AMOUNTS = {100_000, 1_000_000, 5_000_000, 50_000_000}
# Dust threshold — anything at or below this is flagged
DUST_LIMIT_SATS = 1000
# High fee threshold
HIGH_FEE_THRESHOLD = 50
# Round-number payment detection
ROUND_AMOUNT_SATS = [100_000, 500_000, 1_000_000, 5_000_000, 10_000_000,
                     50_000_000, 100_000_000]

SLIP132_TO_BIP32 = {
    "xpub": ("0488b21e", "0488b21e"),
    "ypub": ("049d7cb2", "0488b21e"),
    "zpub": ("04b24746", "0488b21e"),
    "Ypub": ("0295b43f", "0488b21e"),
    "Zpub": ("02aa7ed3", "0488b21e"),
    "tpub": ("043587cf", "043587cf"),
    "upub": ("044a5262", "043587cf"),
    "vpub": ("045f1cf6", "043587cf"),
    "Upub": ("024289ef", "043587cf"),
    "Vpub": ("02575483", "043587cf"),
}

session = requests.Session()
session.headers.update({"User-Agent": "Stealth-Wallet-Analyzer/1.0"})

_request_count = 0
_scan_start_offset = 0


def configure_proxy(proxy_url):
    """
    Route all API requests through a SOCKS5 proxy (e.g. Tor).
    Pass None or empty string to clear.
    Requires: pip install requests[socks]
    """
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}
        debug(f"[proxy] Routing requests through {proxy_url}")
    else:
        session.proxies = {}
        debug("[proxy] No proxy — direct connections")


def debug(*args):
    print(*args, file=sys.stderr)

def satoshis(btc):
    return int(round(float(btc) * 100_000_000))

def _rate_limit_delay():
    """
    Progressive rate-limiting based on how deep into the address space we are.
    The further into the wallet we scan, the more cautious we are with API calls
    to avoid triggering rate limits or IP blocks on Blockstream/Mempool.

    Tiers:
      offset   0–99:  base delay (0.25s), burst every 10 reqs (0.75s)
      offset 100–199: 2x delay (0.5s),  burst every 10 reqs (1.5s)
      offset 200–299: 3x delay (0.75s), burst every 10 reqs (2.25s)
      offset 300+:    4x delay (1.0s),  burst every 10 reqs (3.0s)
    """
    global _request_count
    _request_count += 1

    if _scan_start_offset >= 300:
        delay = REQUEST_DELAY_LARGE * 2.0   # 1.0s
    elif _scan_start_offset >= 200:
        delay = REQUEST_DELAY_LARGE * 1.5   # 0.75s
    elif _scan_start_offset >= 100:
        delay = REQUEST_DELAY_LARGE         # 0.5s
    else:
        delay = REQUEST_DELAY               # 0.25s

    # Every 10th request: extended pause to let the server breathe
    if _request_count % 10 == 0:
        time.sleep(delay * 3)
    else:
        time.sleep(delay)

def parse_descriptor(descriptor):
    if descriptor is None:
        raise ValueError("descriptor is required")
    if not isinstance(descriptor, str):
        raise ValueError("descriptor must be a string")

    desc = descriptor.strip()
    if not desc:
        raise ValueError("descriptor cannot be empty")

    if "#" in desc:
        desc = desc.split("#", 1)[0].strip()

    pattern = re.compile(
        r"""
        ^wpkh\(
            (?:
                \[
                    (?P<fingerprint>[0-9a-fA-F]{8})
                    (?P<origin_path>/[^\]]+)?
                \]
            )?
            (?P<extpub>[A-Za-z0-9]+)
            /
            (?P<branch>0|1)
            /\*
        \)$
        """,
        re.VERBOSE,
    )

    m = pattern.fullmatch(desc)
    if not m:
        raise ValueError(
            "unsupported descriptor format: expected wpkh([fingerprint/path]xpub.../0/*)"
        )

    fingerprint = m.group("fingerprint")
    origin_path = m.group("origin_path")
    extpub = m.group("extpub")
    branch = int(m.group("branch"))

    if fingerprint is not None:
        fingerprint = fingerprint.lower()
    if origin_path is not None:
        origin_path = origin_path.lstrip("/")
    else:
        origin_path = ""

    prefix = extpub[:4]
    if prefix not in SLIP132_TO_BIP32:
        raise ValueError(f"unsupported extended key prefix: {prefix}")

    return {
        "fingerprint": fingerprint,
        "origin_path": origin_path,
        "extpub": extpub,
        "branch": branch,
        "descriptor": desc,
    }

def convert_slip132_to_bip32(extpub):
    prefix = extpub[:4]
    src_hex, dst_hex = SLIP132_TO_BIP32[prefix]
    raw = base58.b58decode_check(extpub)
    if raw[:4].hex() != src_hex:
        raise ValueError(f"Unexpected version bytes for {prefix}")
    converted = bytes.fromhex(dst_hex) + raw[4:]
    return base58.b58encode_check(converted).decode()

def xpub_net_and_key(extpub):
    prefix = extpub[:4]
    mainnet = prefix in {"xpub", "ypub", "zpub", "Ypub", "Zpub"}
    testnet = prefix in {"tpub", "upub", "vpub", "Upub", "Vpub"}
    if not (mainnet or testnet):
        raise ValueError(f"Unsupported extended pub prefix: {prefix}")
    return "mainnet" if mainnet else "testnet"

def derive_wpkh_addresses(extpub, count, branch, start_index=0):
    net = xpub_net_and_key(extpub)
    bip32_key = convert_slip132_to_bip32(extpub)
    account_ctx = Bip32Secp256k1.FromExtendedKey(bip32_key)
    branch_ctx = account_ctx.ChildKey(branch)

    addrs = []
    for i in range(start_index, start_index + count):
        child = branch_ctx.ChildKey(i)
        pubkey_bytes = child.PublicKey().RawCompressed().ToBytes()
        hrp = (
            CoinsConf.BitcoinMainNet.ParamByKey("p2wpkh_hrp")
            if net == "mainnet"
            else CoinsConf.BitcoinTestNet.ParamByKey("p2wpkh_hrp")
        )
        addr = P2WPKHAddrEncoder.EncodeKey(pubkey_bytes, hrp=hrp)
        addrs.append(addr)

    return addrs

def api_get(path):
    _rate_limit_delay()
    for attempt in range(MAX_RETRIES):
        for base in (_primary, _fallback):
            try:
                url = f"{base}{path}"
                r = session.get(url, timeout=(5, 15))
                if r.status_code == 429:
                    wait = RETRY_BACKOFF_BASE ** (attempt + 2)
                    debug(f"Rate limited by {base}, waiting {wait:.1f}s...")
                    time.sleep(wait)
                    continue
                r.raise_for_status()
                return r.json()
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 429:
                    wait = RETRY_BACKOFF_BASE ** (attempt + 2)
                    debug(f"Rate limited (HTTPError) on {base}, waiting {wait:.1f}s...")
                    time.sleep(wait)
                    continue
                debug(f"api_get HTTPError on {base}: {e}, trying fallback...")
            except Exception as e:
                debug(f"api_get failed on {base}: {e}, trying fallback...")
        if attempt < MAX_RETRIES - 1:
            wait = RETRY_BACKOFF_BASE ** attempt
            debug(f"All endpoints failed (attempt {attempt+1}/{MAX_RETRIES}), retrying in {wait:.1f}s...")
            time.sleep(wait)
    raise RuntimeError(f"All API endpoints failed for path: {path}")

def address_stats(address):
    return api_get(f"/address/{address}")

def address_txs(address):
    txs = []
    batch = api_get(f"/address/{address}/txs")
    txs.extend(batch)
    while len(batch) == 25:
        last_txid = batch[-1]["txid"]
        batch = api_get(f"/address/{address}/txs/chain/{last_txid}")
        if not batch:
            break
        txs.extend(batch)
    return txs

def address_utxos(address):
    return api_get(f"/address/{address}/utxo")

def collect_wallet_data(addresses):
    tx_map = {}
    addr_txs = defaultdict(list)
    utxos = []
    active_addresses = []
    addr_received_outputs = defaultdict(list)

    for addr in addresses:
        try:
            stats = address_stats(addr)
        except Exception as e:
            debug(f"stats error for {addr}: {e}")
            continue

        chain_stats = stats.get("chain_stats", {}) or {}
        mempool_stats = stats.get("mempool_stats", {}) or {}

        tx_count = chain_stats.get("tx_count", 0) + mempool_stats.get("tx_count", 0)
        funded_count = chain_stats.get("funded_txo_count", 0) + mempool_stats.get("funded_txo_count", 0)
        spent_count = chain_stats.get("spent_txo_count", 0) + mempool_stats.get("spent_txo_count", 0)

        if tx_count == 0 and funded_count == 0 and spent_count == 0:
            continue

        active_addresses.append(addr)

        try:
            txs = address_txs(addr)
        except Exception as e:
            debug(f"tx error for {addr}: {e}")
            txs = []

        for tx in txs:
            txid = tx["txid"]
            tx_map[txid] = tx
            received = False
            sent = False
            recv_value = 0
            spend_value = 0

            for vin in tx.get("vin", []):
                prev = vin.get("prevout") or {}
                if prev.get("scriptpubkey_address") == addr:
                    sent = True
                    spend_value += prev.get("value", 0)

            for vout in tx.get("vout", []):
                if vout.get("scriptpubkey_address") == addr:
                    received = True
                    recv_value += vout.get("value", 0)
                    addr_received_outputs[addr].append({
                        "txid": txid,
                        "value": vout.get("value", 0),
                        "n": vout.get("n", 0),
                    })

            if received:
                addr_txs[addr].append({
                    "txid": txid,
                    "category": "receive",
                    "amount": recv_value / 100_000_000,
                    "confirmations": 1 if tx.get("status", {}).get("confirmed") else 0,
                    "blockheight": tx.get("status", {}).get("block_height", 0),
                })
            if sent:
                addr_txs[addr].append({
                    "txid": txid,
                    "category": "send",
                    "amount": -(spend_value / 100_000_000),
                    "confirmations": 1 if tx.get("status", {}).get("confirmed") else 0,
                    "blockheight": tx.get("status", {}).get("block_height", 0),
                })

        try:
            addr_unspent = address_utxos(addr)
        except Exception as e:
            debug(f"utxo error for {addr}: {e}")
            addr_unspent = []

        for u in addr_unspent:
            status = u.get("status", {}) or {}
            utxos.append({
                "address": addr,
                "txid": u.get("txid", ""),
                "vout": u.get("vout", 0),
                "amount": u.get("value", 0) / 100_000_000,
                "confirmations": 1 if status.get("confirmed") else 0,
                "blockheight": status.get("block_height", 0),
            })

    return tx_map, addr_txs, utxos, active_addresses, addr_received_outputs


class TxGraph:
    def __init__(self, addr_map, tx_map, addr_txs, utxos, addr_received_outputs=None):
        self.addr_map = addr_map
        self.our_addrs = set(addr_map.keys())
        self.tx_map = tx_map
        self.addr_txs = addr_txs
        self.utxos = utxos
        self.our_txids = set(tx_map.keys())
        self.addr_received_outputs = addr_received_outputs or defaultdict(list)

    def fetch_tx(self, txid):
        return self.tx_map.get(txid)

    def is_ours(self, address):
        return address in self.our_addrs

    def get_input_addresses(self, txid):
        tx = self.fetch_tx(txid)
        if not tx:
            return []
        addrs = []
        for vin in tx.get("vin", []):
            prev = vin.get("prevout") or {}
            addrs.append({
                "address": prev.get("scriptpubkey_address", ""),
                "value": prev.get("value", 0) / 100_000_000,
                "txid": vin.get("txid", ""),
                "vout": vin.get("vout", 0),
            })
        return addrs

    def get_output_addresses(self, txid):
        tx = self.fetch_tx(txid)
        if not tx:
            return []
        addrs = []
        for vout in tx.get("vout", []):
            addrs.append({
                "address": vout.get("scriptpubkey_address", ""),
                "value": vout.get("value", 0) / 100_000_000,
                "n": vout.get("n", 0),
                "type": vout.get("scriptpubkey_type", "unknown"),
            })
        return addrs

    def get_script_type(self, address):
        """Return script type for an address — from addr_map or address-prefix heuristic."""
        meta = self.addr_map.get(address)
        if meta:
            return meta.get("type", "unknown")
        if address.startswith(("bc1q", "tb1q", "bcrt1q")):
            return "p2wpkh"
        if address.startswith(("bc1p", "tb1p", "bcrt1p")):
            return "p2tr"
        if address.startswith(("3", "2")):
            return "p2sh-p2wpkh"
        if address.startswith(("1", "m", "n")):
            return "p2pkh"
        return "unknown"


# ─────────────────────────────────────────────────────────
# DETECTORS
# ─────────────────────────────────────────────────────────

def detect_address_reuse(g):
    """
    Flag any wallet address that received funds in 2+ distinct transactions.
    Checks both unspent and historical (spent) receives.
    """
    findings = []
    for addr in g.our_addrs:
        receive_txids = set()
        for entry in g.addr_txs.get(addr, []):
            if entry["category"] == "receive":
                receive_txids.add(entry["txid"])
        for out in g.addr_received_outputs.get(addr, []):
            receive_txids.add(out["txid"])

        if len(receive_txids) >= 2:
            findings.append({
                "type": "ADDRESS_REUSE",
                "severity": "HIGH",
                "description": (
                    f"Address {addr[:12]}\u2026 reused: received funds in "
                    f"{len(receive_txids)} separate transaction(s)."
                ),
                "details": {
                    "address": addr,
                    "receive_count": len(receive_txids),
                    "txids": sorted(receive_txids)[:10],
                },
                "correction": "Generate a fresh address for every payment. BIP44 wallets do this automatically — never reuse addresses manually.",
            })
    return findings


def detect_dust(g):
    """
    Detect dust in two ways:
    1. Unspent dust UTXOs currently in the wallet (active risk)
    2. Historical dust outputs received (already spent — still reveals a dust attack attempt)
    """
    findings = []
    reported = set()

    current_unspent_txids = {(u["address"], u["txid"], u["vout"]) for u in g.utxos}
    for u in g.utxos:
        sats = satoshis(u["amount"])
        if sats <= DUST_LIMIT_SATS and g.is_ours(u.get("address", "")):
            key = (u["address"], u["txid"], u["vout"])
            reported.add(key)
            severity = "HIGH" if sats <= 546 else "MEDIUM"
            findings.append({
                "type": "DUST",
                "severity": severity,
                "description": (
                    f"Unspent dust UTXO at {u['address'][:12]}\u2026 "
                    f"({sats:,} sats). If spent with other inputs, it links your UTXOs together."
                ),
                "details": {
                    "address": u["address"],
                    "sats": sats,
                    "txid": u["txid"],
                    "vout": u["vout"],
                    "status": "unspent",
                },
                "correction": "Do not spend this dust. Use coin control to exclude it, or consolidate with a dedicated coinjoin tool.",
            })

    for addr, outputs in g.addr_received_outputs.items():
        if not g.is_ours(addr):
            continue
        for out in outputs:
            sats = out["value"]
            key = (addr, out["txid"], out["n"])
            if sats <= DUST_LIMIT_SATS and key not in reported and key not in current_unspent_txids:
                reported.add(key)
                findings.append({
                    "type": "DUST",
                    "severity": "LOW",
                    "description": (
                        f"Historical dust output at {addr[:12]}\u2026 "
                        f"({sats:,} sats, already spent). Indicates a past dust attack attempt."
                    ),
                    "details": {
                        "address": addr,
                        "sats": sats,
                        "txid": out["txid"],
                        "vout": out["n"],
                        "status": "spent",
                    },
                    "correction": "This dust was already spent — if merged with other UTXOs in the same transaction, your addresses may have been linked. Review the spending transaction.",
                })

    return findings


def detect_dust_spending(g):
    """Detect transactions that spend dust alongside normal inputs."""
    findings = []
    DUST_SATS = 1000

    for txid in g.our_txids:
        input_addrs = g.get_input_addresses(txid)
        if not input_addrs or len(input_addrs) < 2:
            continue

        dust_inputs = []
        normal_inputs = []
        for ia in input_addrs:
            if not g.is_ours(ia["address"]):
                continue
            sats = satoshis(ia["value"])
            if sats <= DUST_SATS:
                dust_inputs.append(ia)
            elif sats > 10_000:
                normal_inputs.append(ia)

        if dust_inputs and normal_inputs:
            findings.append({
                "type": "DUST_SPENDING",
                "severity": "HIGH",
                "description": (
                    f"TX {txid[:16]}\u2026 spends {len(dust_inputs)} dust input(s) alongside "
                    f"{len(normal_inputs)} normal input(s) — permanently links these addresses."
                ),
                "details": {
                    "txid": txid,
                    "dust_inputs": [{"address": d["address"], "sats": satoshis(d["value"])} for d in dust_inputs],
                    "normal_inputs": [{"address": n["address"], "amount_btc": round(n["value"], 8)} for n in normal_inputs],
                },
                "correction": (
                    "Freeze dust UTXOs in your wallet to prevent automatic selection. "
                    "Never manually include a dust UTXO in a transaction that also spends normal UTXOs. "
                    "If dust must be reclaimed, do so in isolation via a dedicated CoinJoin."
                ),
            })
    return findings


def detect_cioh(g):
    findings = []
    for txid in g.our_txids:
        inputs = g.get_input_addresses(txid)
        if len(inputs) < 2:
            continue
        our_inputs = [i for i in inputs if g.is_ours(i["address"])]
        if len(our_inputs) >= 2:
            n_ours = len(our_inputs)
            total = len(inputs)
            ownership_pct = round(n_ours / total * 100)
            severity = "CRITICAL" if n_ours == total else "HIGH"
            findings.append({
                "type": "CIOH",
                "severity": severity,
                "description": f"TX {txid[:16]}\u2026 merges {n_ours}/{total} of your inputs ({ownership_pct}% ownership).",
                "details": {
                    "txid": txid,
                    "our_inputs": n_ours,
                    "total_inputs": total,
                    "ownership_pct": ownership_pct,
                    "our_input_addresses": [i["address"] for i in our_inputs][:5],
                },
                "correction": "Use coin control to avoid merging multiple UTXOs in a single transaction. If consolidation is unavoidable, do it via CoinJoin.",
            })
    return findings


def detect_change_detection(g):
    """
    Detect transactions where the change output is easily distinguishable via
    standard heuristics: round payment vs non-round change, script type mismatch,
    internal derivation path.
    """
    findings = []

    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue
        outputs = g.get_output_addresses(txid)
        input_addrs = g.get_input_addresses(txid)
        if not outputs or len(outputs) < 2:
            continue

        our_in = [ia for ia in input_addrs if g.is_ours(ia["address"])]
        if not our_in:
            continue

        our_outs = [o for o in outputs if g.is_ours(o["address"])]
        ext_outs = [o for o in outputs if not g.is_ours(o["address"])
                    and o.get("type") != "op_return"]

        if not our_outs or not ext_outs:
            continue

        problems = []
        for change in our_outs:
            ch_sats = satoshis(change["value"])
            ch_round = (ch_sats % 100_000 == 0 or ch_sats % 1_000_000 == 0)

            for payment in ext_outs:
                pay_sats = satoshis(payment["value"])
                pay_round = (pay_sats % 100_000 == 0 or pay_sats % 1_000_000 == 0)

                if pay_round and not ch_round:
                    problems.append(
                        f"Round payment ({pay_sats:,} sats) vs non-round change ({ch_sats:,} sats)"
                    )

                in_types = {g.get_script_type(ia["address"]) for ia in our_in}
                ch_type = g.get_script_type(change["address"])
                pay_type = g.get_script_type(payment["address"])
                if ch_type in in_types and ch_type != pay_type:
                    problems.append(
                        f"Change script type ({ch_type}) matches input but differs from payment ({pay_type})"
                    )

            ch_meta = g.addr_map.get(change["address"], {})
            if ch_meta.get("internal"):
                if "BIP-44 internal path" not in " ".join(problems):
                    problems.append(
                        "Change uses an internal (BIP-44 /1/*) derivation path — standard wallet change pattern"
                    )

        if problems:
            findings.append({
                "type": "CHANGE_DETECTION",
                "severity": "MEDIUM",
                "description": (
                    f"TX {txid[:16]}\u2026 has identifiable change output(s) "
                    f"({len(problems)} heuristic(s) matched)."
                ),
                "details": {
                    "txid": txid,
                    "reasons": problems[:6],
                    "change_outputs": [
                        {"address": co["address"], "amount_btc": round(co["value"], 8)}
                        for co in our_outs
                    ],
                },
                "correction": (
                    "Use PayJoin (BIP-78) so the receiver also contributes an input, breaking the payment/change heuristic. "
                    "Alternatively, select a UTXO that exactly covers the payment amount (no change output needed). "
                    "Ensure your change address uses the same script type as the payment address."
                ),
            })

    return findings


def detect_consolidation(g):
    """
    Detect UTXOs born from a prior consolidation transaction
    (>= 3 inputs, <= 2 outputs).
    """
    findings = []
    CONSOLIDATION_THRESHOLD = 3
    seen_txids = set()

    for utxo in g.utxos:
        if not g.is_ours(utxo.get("address", "")):
            continue
        parent_txid = utxo["txid"]
        if parent_txid in seen_txids:
            continue
        parent = g.fetch_tx(parent_txid)
        if not parent:
            continue
        n_in = len(parent.get("vin", []))
        n_out = len(parent.get("vout", []))
        if n_in >= CONSOLIDATION_THRESHOLD and n_out <= 2:
            seen_txids.add(parent_txid)
            parent_inputs = g.get_input_addresses(parent_txid)
            our_parent_in = [ia for ia in parent_inputs if g.is_ours(ia["address"])]
            findings.append({
                "type": "CONSOLIDATION",
                "severity": "MEDIUM",
                "description": (
                    f"TX {parent_txid[:16]}\u2026 is a consolidation: {n_in} inputs \u2192 {n_out} output(s). "
                    f"{len(our_parent_in)} of your addresses were merged."
                ),
                "details": {
                    "txid": parent_txid,
                    "total_inputs": n_in,
                    "our_inputs": len(our_parent_in),
                    "total_outputs": n_out,
                    "our_input_addresses": [ia["address"] for ia in our_parent_in][:5],
                },
                "correction": (
                    "Avoid consolidating UTXOs outside of a CoinJoin. "
                    "If you must consolidate, do it in a single dedicated transaction using only same-source UTXOs, "
                    "not mixed with UTXOs from different origins."
                ),
            })

    return findings


def run_all_detectors(g):
    findings = []
    warnings = []

    detector_funcs = [
        detect_cioh,
        detect_address_reuse,
        detect_dust,
        detect_dust_spending,
        detect_change_detection,
        detect_consolidation,
    ]

    for fn in detector_funcs:
        try:
            results = fn(g)
            for r in results:
                if r.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    findings.append(r)
                else:
                    warnings.append(r)
        except Exception as e:
            debug(f"Detector {fn.__name__} failed: {e}")

    return findings, warnings


def analyze(
    descriptor_str,
    offset=0,
    count=60,
    branch_override=None,
    auto_gap=False,
):
    global _scan_start_offset
    _scan_start_offset = offset

    parsed = parse_descriptor(descriptor_str)
    extpub = parsed["extpub"]
    branch = branch_override if branch_override is not None else parsed["branch"]

    if auto_gap:
        return _analyze_auto_gap(extpub, branch, parsed, offset)

    addresses = derive_wpkh_addresses(extpub, count, branch, start_index=offset)
    addr_map = {
        addr: {
            "index": offset + i,
            "branch": branch,
            "internal": branch == 1,
            "type": "p2wpkh",
        }
        for i, addr in enumerate(addresses)
    }

    tx_map, addr_txs, utxos, active_addresses, addr_received_outputs = collect_wallet_data(addresses)

    g = TxGraph(addr_map, tx_map, addr_txs, utxos, addr_received_outputs)
    findings, warnings_list = run_all_detectors(g)

    stats = {
        "addresses_scanned": len(addresses),
        "active_addresses": len(active_addresses),
        "transactions_analyzed": len(tx_map),
        "utxos_found": len(utxos),
    }

    return {
        "scan_window": {
            "from_index": offset,
            "to_index": offset + len(addresses) - 1,
        },
        "stats": stats,
        "findings": findings,
        "warnings": warnings_list,
        "summary": {
            "findings": len(findings),
            "warnings": len(warnings_list),
            "clean": len(findings) == 0 and len(warnings_list) == 0,
        },
    }


def _analyze_auto_gap(extpub, branch, parsed, start_offset=0):
    """
    Auto gap-limit scan: keep scanning in batches of AUTO_BATCH_SIZE
    until GAP_LIMIT consecutive inactive addresses are found,
    or MAX_AUTO_ADDRESSES is reached.
    """
    all_tx_maps = {}
    all_addr_txs = defaultdict(list)
    all_utxos = []
    all_active = []
    all_addr_received_outputs = defaultdict(list)
    all_addr_maps = {}

    consecutive_inactive = 0
    current_index = start_offset
    total_scanned = 0

    while consecutive_inactive < GAP_LIMIT and total_scanned < MAX_AUTO_ADDRESSES:
        batch_size = min(AUTO_BATCH_SIZE, MAX_AUTO_ADDRESSES - total_scanned)
        addresses = derive_wpkh_addresses(extpub, batch_size, branch, start_index=current_index)

        for i, addr in enumerate(addresses):
            all_addr_maps[addr] = {
                "index": current_index + i,
                "branch": branch,
                "internal": branch == 1,
                "type": "p2wpkh",
            }

        tx_map, addr_txs, utxos, active_addresses, addr_received_outputs = collect_wallet_data(addresses)

        all_tx_maps.update(tx_map)
        for addr, txlist in addr_txs.items():
            all_addr_txs[addr].extend(txlist)
        all_utxos.extend(utxos)
        all_active.extend(active_addresses)
        for addr, outs in addr_received_outputs.items():
            all_addr_received_outputs[addr].extend(outs)

        inactive_in_batch = [a for a in addresses if a not in active_addresses]
        if len(inactive_in_batch) == len(addresses):
            consecutive_inactive += len(addresses)
        else:
            consecutive_inactive = 0

        current_index += batch_size
        total_scanned += batch_size

        debug(f"[auto-gap] scanned {total_scanned} addrs, {consecutive_inactive} consecutive inactive")

    g = TxGraph(all_addr_maps, all_tx_maps, all_addr_txs, all_utxos, all_addr_received_outputs)
    findings, warnings_list = run_all_detectors(g)

    stats = {
        "addresses_scanned": total_scanned,
        "active_addresses": len(all_active),
        "transactions_analyzed": len(all_tx_maps),
        "utxos_found": len(all_utxos),
    }

    return {
        "scan_window": {
            "from_index": start_offset,
            "to_index": current_index - 1,
        },
        "stats": stats,
        "findings": findings,
        "warnings": warnings_list,
        "summary": {
            "findings": len(findings),
            "warnings": len(warnings_list),
            "clean": len(findings) == 0 and len(warnings_list) == 0,
        },
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Stealth — Bitcoin Wallet Privacy Analyzer")
    parser.add_argument("descriptor", help="wpkh() descriptor string")
    parser.add_argument("--offset", type=int, default=0, help="Start address index")
    parser.add_argument("--count", type=int, default=60, help="Number of addresses to scan")
    parser.add_argument("--branch", type=int, choices=[0, 1], default=None,
                        help="Branch override: 0=receive, 1=change")
    parser.add_argument("--auto", action="store_true", help="Auto gap-limit scan")
    parser.add_argument("--proxy", type=str, default=None,
                        help="SOCKS5 proxy URL (e.g. socks5h://127.0.0.1:9050)")
    args = parser.parse_args()

    if args.proxy:
        configure_proxy(args.proxy)

    result = analyze(
        args.descriptor,
        offset=args.offset,
        count=args.count,
        branch_override=args.branch,
        auto_gap=args.auto,
    )
    print(json.dumps(result, indent=2))
