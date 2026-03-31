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
# Dust threshold
DUST_LIMIT_SATS = 1000
# Max fee rate considered "normal" (sat/vB); above suggests privacy-seeking
HIGH_FEE_THRESHOLD = 50
# Round-number payment detection threshold (sats)
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

def debug(*args):
    print(*args, file=sys.stderr)

def satoshis(btc):
    return int(round(float(btc) * 100_000_000))

def _rate_limit_delay():
    global _request_count
    _request_count += 1
    delay = REQUEST_DELAY_LARGE if _scan_start_offset > 100 else REQUEST_DELAY
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

    return tx_map, addr_txs, utxos, active_addresses


class TxGraph:
    def __init__(self, addr_map, tx_map, addr_txs, utxos):
        self.addr_map = addr_map
        self.our_addrs = set(addr_map.keys())
        self.tx_map = tx_map
        self.addr_txs = addr_txs
        self.utxos = utxos
        self.our_txids = set(tx_map.keys())

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


# ─────────────────────────────────────────────────────────
# DETECTORS
# ─────────────────────────────────────────────────────────

def detect_address_reuse(g):
    findings = []
    for addr in g.our_addrs:
        receive_txids = set()
        for entry in g.addr_txs.get(addr, []):
            if entry["category"] == "receive":
                receive_txids.add(entry["txid"])
        if len(receive_txids) >= 2:
            findings.append({
                "type": "ADDRESS_REUSE",
                "severity": "HIGH",
                "description": f"Address {addr} reused across {len(receive_txids)} transactions",
                "details": {
                    "address": addr,
                    "tx_count": len(receive_txids),
                    "txids": sorted(receive_txids),
                },
                "correction": "Generate a fresh address for every payment received.",
            })
    return findings


def detect_dust(g):
    findings = []
    for u in g.utxos:
        sats = satoshis(u["amount"])
        if sats <= DUST_LIMIT_SATS and g.is_ours(u.get("address", "")):
            findings.append({
                "type": "DUST",
                "severity": "MEDIUM" if sats > 546 else "HIGH",
                "description": f"Dust UTXO at {u['address']} ({sats} sats, unspent)",
                "details": {
                    "address": u["address"],
                    "sats": sats,
                    "txid": u["txid"],
                    "vout": u["vout"],
                },
                "correction": "Avoid spending dust with normal inputs — it links UTXOs together.",
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
            findings.append({
                "type": "CIOH",
                "severity": "HIGH",
                "description": f"TX {txid} merges {len(our_inputs)} of your inputs",
                "details": {
                    "txid": txid,
                    "our_inputs": len(our_inputs),
                    "total_inputs": len(inputs),
                },
                "correction": "Use coin control to avoid merging multiple UTXOs.",
            })
    return findings


def detect_payjoin_interaction(g):
    """
    PayJoin (P2EP) detection heuristic:
    A transaction where:
    - at least one of OUR addresses is in the inputs AND
    - at least one external address is also in the inputs AND
    - at least one of our addresses receives an output
    This pattern is consistent with PayJoin — the recipient adds their own input.
    We flag it as INFORMATIONAL: the user may have used PayJoin (good), or may
    have unknowingly participated in a transaction with external inputs (risky).
    """
    findings = []
    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue
        inputs = g.get_input_addresses(txid)
        if len(inputs) < 2:
            continue

        our_input_addrs = [i["address"] for i in inputs if g.is_ours(i["address"])]
        ext_input_addrs = [i["address"] for i in inputs if not g.is_ours(i["address"]) and i["address"]]

        if not our_input_addrs or not ext_input_addrs:
            continue

        # check if we also receive an output in the same tx
        our_output_addrs = [
            vout.get("scriptpubkey_address", "")
            for vout in tx.get("vout", [])
            if g.is_ours(vout.get("scriptpubkey_address", ""))
        ]

        if our_output_addrs:
            findings.append({
                "type": "PAYJOIN_INTERACTION",
                "severity": "LOW",
                "description": (
                    f"TX {txid[:16]}… has mixed inputs (yours + external) and outputs to your wallet. "
                    "Consistent with a PayJoin/P2EP transaction."
                ),
                "details": {
                    "txid": txid,
                    "our_inputs": len(our_input_addrs),
                    "external_inputs": len(ext_input_addrs),
                    "our_outputs": len(our_output_addrs),
                },
                "correction": (
                    "If you intentionally used PayJoin — great, this improves privacy. "
                    "If not, an external party contributed inputs alongside yours, which could be a privacy risk."
                ),
            })
    return findings


def detect_whirlpool_patterns(g):
    """
    Whirlpool CoinJoin detection:
    - Transaction has exactly 5 outputs of equal value matching a known Whirlpool pool amount
    - All outputs are P2WPKH (bc1q…)
    - At least one output goes to one of our addresses
    """
    findings = []
    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue

        vouts = tx.get("vout", [])
        if len(vouts) < 4:
            continue

        # Collect output values
        output_values = [vout.get("value", 0) for vout in vouts]

        # Check for equal-value outputs matching Whirlpool pools
        for pool_sats in WHIRLPOOL_POOL_AMOUNTS:
            matching = [v for v in output_values if v == pool_sats]
            if len(matching) >= 4:  # Whirlpool typically has 5 equal outputs
                # Check if any go to us
                our_outputs = [
                    vout for vout in vouts
                    if vout.get("value") == pool_sats and g.is_ours(vout.get("scriptpubkey_address", ""))
                ]
                if our_outputs:
                    findings.append({
                        "type": "WHIRLPOOL_COINJOIN",
                        "severity": "LOW",
                        "description": (
                            f"TX {txid[:16]}… matches Whirlpool CoinJoin pattern "
                            f"({len(matching)} equal outputs of {pool_sats:,} sats)."
                        ),
                        "details": {
                            "txid": txid,
                            "pool_amount_sats": pool_sats,
                            "equal_output_count": len(matching),
                            "our_mixed_outputs": len(our_outputs),
                        },
                        "correction": (
                            "This looks like a Whirlpool mix — good for privacy! "
                            "Make sure post-mix UTXOs are spent carefully to preserve the anonymity set."
                        ),
                    })
                    break  # one finding per tx is enough
    return findings


def detect_fee_fingerprinting(g):
    """
    Fee fingerprinting detection:
    Some wallets use distinctive fee-rate patterns (e.g. always round sat/vB like 1, 2, 5, 10)
    or specific fee calculation methods (e.g. fee is exactly divisible by output count).
    We detect:
    1. Round fee-rate pattern: fee rate is a round number (1, 2, 5, 10, 20, 50 sat/vB)
    2. Batched payment fingerprint: single tx sends to 5+ external outputs
       (suggests a custodial or corporate batcher)
    3. Unnecessary change fingerprint: change output is disproportionately small vs. payment
    """
    findings = []
    round_fee_rates = {1, 2, 5, 10, 15, 20, 25, 50, 100}
    round_fee_txids = []
    batch_payment_txids = []
    tiny_change_txids = []

    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue

        fee = tx.get("fee", 0)
        weight = tx.get("weight", 0)
        vsize = max(1, (weight + 3) // 4) if weight else 0

        # 1. Round fee rate detection
        if vsize > 0 and fee > 0:
            fee_rate = round(fee / vsize)
            if fee_rate in round_fee_rates:
                round_fee_txids.append({
                    "txid": txid,
                    "fee_rate_sat_vb": fee_rate,
                    "fee_sats": fee,
                })

        # 2. Batch payment detection (many external outputs)
        vouts = tx.get("vout", [])
        external_outputs = [
            vout for vout in vouts
            if not g.is_ours(vout.get("scriptpubkey_address", ""))
            and vout.get("scriptpubkey_type") != "op_return"
        ]
        if len(external_outputs) >= 5:
            batch_payment_txids.append({
                "txid": txid,
                "external_output_count": len(external_outputs),
            })

        # 3. Tiny change output detection
        our_outputs = [
            vout for vout in vouts
            if g.is_ours(vout.get("scriptpubkey_address", ""))
        ]
        non_our_outputs = [
            vout for vout in vouts
            if not g.is_ours(vout.get("scriptpubkey_address", ""))
            and vout.get("scriptpubkey_type") != "op_return"
        ]
        if our_outputs and non_our_outputs:
            our_max = max(v.get("value", 0) for v in our_outputs)
            ext_max = max(v.get("value", 0) for v in non_our_outputs)
            # If our "change" is less than 1% of the payment, it's a fingerprint
            if ext_max > 0 and our_max / ext_max < 0.01 and our_max < 10_000:
                tiny_change_txids.append({
                    "txid": txid,
                    "change_sats": our_max,
                    "payment_sats": ext_max,
                })

    if round_fee_txids:
        findings.append({
            "type": "FEE_FINGERPRINTING",
            "severity": "LOW",
            "description": (
                f"{len(round_fee_txids)} transaction(s) use a round fee rate "
                "(e.g. 1, 5, 10 sat/vB) — a fingerprint of some wallet software."
            ),
            "details": {
                "transactions": round_fee_txids[:10],  # cap at 10
                "count": len(round_fee_txids),
            },
            "correction": (
                "Use wallets that calculate fee rates dynamically (non-round values) "
                "to avoid leaking which software you use."
            ),
        })

    if batch_payment_txids:
        findings.append({
            "type": "BATCH_PAYMENT_FINGERPRINT",
            "severity": "LOW",
            "description": (
                f"{len(batch_payment_txids)} transaction(s) send to 5+ external outputs — "
                "typical of exchange or custodial batching."
            ),
            "details": {
                "transactions": batch_payment_txids[:10],
                "count": len(batch_payment_txids),
            },
            "correction": (
                "If you're not an exchange, avoid sending to many recipients at once; "
                "it reveals your role in the transaction graph."
            ),
        })

    if tiny_change_txids:
        findings.append({
            "type": "TINY_CHANGE_OUTPUT",
            "severity": "MEDIUM",
            "description": (
                f"{len(tiny_change_txids)} transaction(s) have disproportionately tiny change outputs, "
                "making the change output trivially identifiable."
            ),
            "details": {
                "transactions": tiny_change_txids[:10],
                "count": len(tiny_change_txids),
            },
            "correction": (
                "Use wallets with change-output optimization or round-trip payments "
                "to avoid exposing your change address."
            ),
        })

    return findings


def build_addr_map(addresses, branch, start_index=0):
    addr_map = {}
    for i, addr in enumerate(addresses, start=start_index):
        addr_map[addr] = {
            "type": "p2wpkh",
            "internal": branch == 1,
            "index": i,
        }
    return addr_map


def scan_branch(parsed, offset, count, branch):
    global _scan_start_offset
    _scan_start_offset = offset

    addresses = derive_wpkh_addresses(parsed["extpub"], count, branch, start_index=offset)
    addr_map = build_addr_map(addresses, branch, start_index=offset)
    tx_map, addr_txs, utxos, active_addresses = collect_wallet_data(addresses)
    graph = TxGraph(addr_map, tx_map, addr_txs, utxos)

    findings = []
    warnings = []
    findings.extend(detect_address_reuse(graph))
    findings.extend(detect_dust(graph))
    findings.extend(detect_cioh(graph))
    findings.extend(detect_payjoin_interaction(graph))
    findings.extend(detect_whirlpool_patterns(graph))
    findings.extend(detect_fee_fingerprinting(graph))

    return {
        "scan_window": {
            "offset": offset,
            "count": count,
            "from_index": offset,
            "to_index": (offset + len(addresses) - 1) if addresses else offset,
            "branch": branch,
        },
        "stats": {
            "transactions_analyzed": len(graph.our_txids),
            "addresses_derived": len(addresses),
            "utxos_found": len(utxos),
            "active_addresses": len(active_addresses),
        },
        "findings": findings,
        "warnings": warnings,
        "summary": {
            "findings": len(findings),
            "warnings": len(warnings),
            "clean": len(findings) == 0 and len(warnings) == 0,
        },
        "_active_addresses": active_addresses,
    }


def _merge_branch_reports(reports):
    """Merge multiple branch scan reports into one aggregate."""
    all_findings = []
    all_warnings = []
    total_txs = 0
    total_utxos = 0
    total_derived = 0
    total_active = 0
    from_index = None
    to_index = None

    seen_finding_keys = set()

    for r in reports:
        total_txs += r["stats"]["transactions_analyzed"]
        total_utxos += r["stats"]["utxos_found"]
        total_derived += r["stats"]["addresses_derived"]
        total_active += r["stats"]["active_addresses"]

        w = r["scan_window"]
        from_index = w["from_index"] if from_index is None else min(from_index, w["from_index"])
        to_index = w["to_index"] if to_index is None else max(to_index, w["to_index"])

        for f in r["findings"]:
            txid = f.get("txid") or (f.get("details") or {}).get("txid", "")
            addr = f.get("address") or (f.get("details") or {}).get("address", "")
            key = f"{f['type']}::{addr}::{txid}::{f.get('description', '')}"
            if key not in seen_finding_keys:
                seen_finding_keys.add(key)
                all_findings.append(f)

        for w in r["warnings"]:
            txid = w.get("txid") or (w.get("details") or {}).get("txid", "")
            addr = w.get("address") or (w.get("details") or {}).get("address", "")
            key = f"{w['type']}::{addr}::{txid}::{w.get('description', '')}"
            if key not in seen_finding_keys:
                seen_finding_keys.add(key)
                all_warnings.append(w)

    return {
        "stats": {
            "transactions_analyzed": total_txs,
            "addresses_derived": total_derived,
            "utxos_found": total_utxos,
            "active_addresses": total_active,
        },
        "findings": all_findings,
        "warnings": all_warnings,
        "summary": {
            "findings": len(all_findings),
            "warnings": len(all_warnings),
            "clean": len(all_findings) == 0 and len(all_warnings) == 0,
        },
        "aggregate_scan_window": {
            "from_index": from_index or 0,
            "to_index": to_index or 0,
        },
    }


def run_auto_scan(descriptor: str, branch_mode: str = "receive") -> dict:
    global _request_count
    _request_count = 0

    parsed = parse_descriptor(descriptor)

    branches_to_scan = []
    if branch_mode == "change":
        branches_to_scan = [1]
    elif branch_mode == "both":
        branches_to_scan = [0, 1]
    else:
        branches_to_scan = [0]

    all_branch_reports = []
    total_addresses_scanned = 0

    for branch in branches_to_scan:
        offset = 0
        consecutive_inactive = 0
        branch_reports = []

        while offset < MAX_AUTO_ADDRESSES:
            debug(f"Auto-scan branch={branch} offset={offset} gap={consecutive_inactive}/{GAP_LIMIT}")
            report = scan_branch(parsed, offset, AUTO_BATCH_SIZE, branch)
            branch_reports.append(report)
            total_addresses_scanned += report["stats"]["addresses_derived"]

            active_in_batch = report["stats"]["active_addresses"]
            if active_in_batch == 0:
                consecutive_inactive += AUTO_BATCH_SIZE
            else:
                consecutive_inactive = 0

            if consecutive_inactive >= GAP_LIMIT:
                debug(f"Gap limit reached at branch={branch} offset={offset + AUTO_BATCH_SIZE}")
                break

            offset += AUTO_BATCH_SIZE

        if branch_reports:
            merged = _merge_branch_reports(branch_reports)
            merged["_branch"] = branch
            all_branch_reports.append(merged)

    if not all_branch_reports:
        return {
            "stats": {"transactions_analyzed": 0, "addresses_derived": 0, "utxos_found": 0, "active_addresses": 0},
            "findings": [],
            "warnings": [{"type": "NO_ACTIVITY_IN_SCANNED_WINDOW", "severity": "LOW",
                          "description": "No activity found on any scanned branch.",
                          "details": {"branches": branches_to_scan}}],
            "summary": {"findings": 0, "warnings": 1, "clean": False},
            "scan_meta": {"mode": "auto", "branch_mode": branch_mode, "total_addresses_scanned": total_addresses_scanned},
        }

    final = _merge_branch_reports(all_branch_reports)
    final["scan_meta"] = {
        "mode": "auto",
        "branch_mode": branch_mode,
        "branches_checked": branches_to_scan,
        "gap_limit": GAP_LIMIT,
        "total_addresses_scanned": total_addresses_scanned,
        "api_base": API_BASE,
        "request_delay_ms": int(REQUEST_DELAY * 1000),
    }
    final["scan_window"] = {
        "from_index": final["aggregate_scan_window"]["from_index"],
        "to_index": final["aggregate_scan_window"]["to_index"],
        "branch": branches_to_scan[0] if len(branches_to_scan) == 1 else -1,
        "offset": 0,
        "count": total_addresses_scanned,
    }
    return final


def run_scan(descriptor: str, offset: int = 0, count: int = 60, branch_mode: str = "receive") -> dict:
    global _request_count
    _request_count = 0

    if offset < 0:
        raise ValueError("offset must be >= 0")
    if count <= 0 or count > 500:
        raise ValueError("count must be between 1 and 500")

    parsed = parse_descriptor(descriptor)

    if branch_mode == "change":
        branches = [1]
    elif branch_mode == "both":
        branches = [0, 1]
    else:
        branches = [parsed["branch"]]

    reports = []
    for branch in branches:
        report = scan_branch(parsed, offset, count, branch)

        if (
            branch == 0
            and branch_mode == "receive"
            and report["stats"]["active_addresses"] == 0
            and report["stats"]["transactions_analyzed"] == 0
        ):
            fallback = scan_branch(parsed, offset, count, 1)
            has_activity = (
                fallback["stats"]["active_addresses"] > 0
                or fallback["stats"]["transactions_analyzed"] > 0
            )
            if has_activity:
                fallback["warnings"].append({
                    "type": "BRANCH_FALLBACK",
                    "severity": "LOW",
                    "description": "No activity on branch 0; auto-switched to branch 1.",
                    "details": {"requested_branch": 0, "used_branch": 1},
                })
                reports.append(fallback)
                continue
            else:
                report["warnings"].append({
                    "type": "NO_ACTIVITY_IN_SCANNED_WINDOW",
                    "severity": "LOW",
                    "description": "No activity found in this scan window.",
                    "details": {"offset": offset, "count": count},
                })
        reports.append(report)

    if len(reports) == 1:
        final = reports[0]
        final["summary"]["findings"] = len(final["findings"])
        final["summary"]["warnings"] = len(final["warnings"])
        final["summary"]["clean"] = (
            len(final["findings"]) == 0 and len(final["warnings"]) == 0
        )
        final["scan_meta"] = {
            "mode": "manual",
            "branch_mode": branch_mode,
            "branches_checked": branches,
            "api_base": API_BASE,
            "request_delay_ms": int(REQUEST_DELAY * 1000),
        }
        return final

    merged = _merge_branch_reports(reports)
    merged["scan_window"] = {
        "from_index": merged["aggregate_scan_window"]["from_index"],
        "to_index": merged["aggregate_scan_window"]["to_index"],
        "branch": -1,
        "offset": offset,
        "count": count,
    }
    merged["scan_meta"] = {
        "mode": "manual",
        "branch_mode": branch_mode,
        "branches_checked": branches,
        "api_base": API_BASE,
        "request_delay_ms": int(REQUEST_DELAY * 1000),
    }
    return merged
