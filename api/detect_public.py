#!/usr/bin/env python3
import base58
import sys
import re
import os
import json
import time
from collections import defaultdict
from functools import cached_property
from dataclasses import dataclass, field
from typing import Optional, Set, List

import requests
from bip_utils import (
    Bip32Secp256k1,
    P2WPKHAddrEncoder,
    P2SHAddrEncoder,
    P2PKHAddrEncoder,
    P2TRAddrEncoder,
    CoinsConf,
)

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


# ─────────────────────────────────────────────────────────
# SCAN CONFIG
# ─────────────────────────────────────────────────────────

# Full list of detector IDs — used for validation and defaults
ALL_DETECTORS = {
    "address_reuse",
    "dust",
    "dust_spending",
    "cioh",
    "change_detection",
    "consolidation",
    "script_type_mixing",
    "cluster_merge",
    "utxo_age_spread",
    "exchange_origin",
    "tainted_utxo_merge",
    "behavioral_fingerprint",
    "payjoin_interaction",
    "whirlpool_patterns",
    "fee_fingerprinting",
}


@dataclass
class ScanConfig:
    # ── Dust thresholds ──────────────────────────────────
    dust_sats: int = 1000          # outputs at/below this are flagged as dust
    strict_dust_sats: int = 546    # at/below → HIGH severity; above → MEDIUM

    # ── Consolidation ────────────────────────────────────
    consolidation_min_inputs: int = 3
    consolidation_max_outputs: int = 2

    # ── Exchange-origin batch detection ──────────────────
    exchange_batch_outputs: int = 5

    # ── UTXO age / dormancy ──────────────────────────────
    utxo_age_spread_blocks: int = 10          # minimum spread to report
    dormant_utxo_blocks: int = 100            # gap from newest to be "dormant"

    # ── CIOH / dust-spending input thresholds ────────────
    normal_input_min_sats: int = 10_000       # below this is NOT a "normal" input

    # ── Behavioral fingerprint ───────────────────────────
    round_payment_pct_threshold: float = 60.0 # % of round payments to flag
    fee_rate_cv_threshold: float = 0.15       # coefficient of variation
    min_send_txs_for_behavioral: int = 3      # need at least N send-txs

    # ── Fee fingerprinting ───────────────────────────────
    tiny_change_ratio: float = 0.01           # change/payment ratio threshold
    tiny_change_max_sats: int = 10_000

    # ── Enabled detectors (None = all) ───────────────────
    enabled_detectors: Optional[Set[str]] = None

    def is_enabled(self, detector_id: str) -> bool:
        """Return True if the given detector should run."""
        if self.enabled_detectors is None:
            return True
        return detector_id in self.enabled_detectors

    @classmethod
    def from_dict(cls, d: dict) -> "ScanConfig":
        """Build a ScanConfig from a plain dict (e.g. parsed from JSON)."""
        cfg = cls()
        int_fields = {
            "dust_sats", "strict_dust_sats",
            "consolidation_min_inputs", "consolidation_max_outputs",
            "exchange_batch_outputs",
            "utxo_age_spread_blocks", "dormant_utxo_blocks",
            "normal_input_min_sats",
            "min_send_txs_for_behavioral",
            "tiny_change_max_sats",
        }
        float_fields = {
            "round_payment_pct_threshold",
            "fee_rate_cv_threshold",
            "tiny_change_ratio",
        }
        for k, v in d.items():
            if k == "enabled_detectors":
                if v is None:
                    cfg.enabled_detectors = None
                else:
                    cfg.enabled_detectors = {str(x) for x in v} & ALL_DETECTORS
            elif k in int_fields:
                setattr(cfg, k, int(v))
            elif k in float_fields:
                setattr(cfg, k, float(v))
        return cfg


DEFAULT_CONFIG = ScanConfig()


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
    global _request_count
    _request_count += 1
    delay = REQUEST_DELAY_LARGE if _scan_start_offset > 100 else REQUEST_DELAY
    if _request_count % 10 == 0:
        time.sleep(delay * 3)
    else:
        time.sleep(delay)


# ─────────────────────────────────────────────────────────
# DESCRIPTOR PARSING
# ─────────────────────────────────────────────────────────

_KEY_PATTERN = r"""
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
"""

_WPKH_RE = re.compile(r"^wpkh\(" + _KEY_PATTERN + r"\)$", re.VERBOSE)
_TR_RE   = re.compile(r"^tr\("   + _KEY_PATTERN + r"\)$", re.VERBOSE)
_PKH_RE  = re.compile(r"^pkh\("  + _KEY_PATTERN + r"\)$", re.VERBOSE)
_SH_WPKH_RE = re.compile(r"^sh\(wpkh\(" + _KEY_PATTERN + r"\)\)$", re.VERBOSE)

_DESCRIPTOR_TYPES = [
    (_WPKH_RE,    "wpkh",     "p2wpkh"),
    (_TR_RE,      "tr",       "p2tr"),
    (_PKH_RE,     "pkh",      "p2pkh"),
    (_SH_WPKH_RE, "sh(wpkh)", "p2sh-p2wpkh"),
]


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

    for pattern, dtype, script_type in _DESCRIPTOR_TYPES:
        m = pattern.fullmatch(desc)
        if not m:
            continue

        fingerprint = m.group("fingerprint")
        origin_path = m.group("origin_path")
        extpub      = m.group("extpub")
        branch      = int(m.group("branch"))

        if fingerprint is not None:
            fingerprint = fingerprint.lower()
        origin_path = origin_path.lstrip("/") if origin_path else ""

        prefix = extpub[:4]
        if prefix not in SLIP132_TO_BIP32:
            raise ValueError(f"unsupported extended key prefix: {prefix}")

        return {
            "fingerprint": fingerprint,
            "origin_path": origin_path,
            "extpub":      extpub,
            "branch":      branch,
            "dtype":       dtype,
            "script_type": script_type,
            "descriptor":  desc,
        }

    raise ValueError(
        "unsupported descriptor format — expected one of: "
        "wpkh([fp/path]xpub.../0/*), "
        "tr([fp/path]xpub.../0/*), "
        "pkh([fp/path]xpub.../0/*), "
        "sh(wpkh([fp/path]xpub.../0/*))"
    )


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


# ─────────────────────────────────────────────────────────
# ADDRESS DERIVATION
# ─────────────────────────────────────────────────────────

def _child_pubkey_bytes(extpub, branch, index):
    bip32_key = convert_slip132_to_bip32(extpub)
    account_ctx = Bip32Secp256k1.FromExtendedKey(bip32_key)
    child = account_ctx.ChildKey(branch).ChildKey(index)
    return child.PublicKey().RawCompressed().ToBytes()


def _derive_p2wpkh(extpub, count, branch, start_index, net):
    hrp = (
        CoinsConf.BitcoinMainNet.ParamByKey("p2wpkh_hrp")
        if net == "mainnet"
        else CoinsConf.BitcoinTestNet.ParamByKey("p2wpkh_hrp")
    )
    addrs = []
    for i in range(start_index, start_index + count):
        pub = _child_pubkey_bytes(extpub, branch, i)
        addrs.append(P2WPKHAddrEncoder.EncodeKey(pub, hrp=hrp))
    return addrs


def _derive_p2tr(extpub, count, branch, start_index, net):
    hrp = (
        CoinsConf.BitcoinMainNet.ParamByKey("p2tr_hrp")
        if net == "mainnet"
        else CoinsConf.BitcoinTestNet.ParamByKey("p2tr_hrp")
    )
    addrs = []
    for i in range(start_index, start_index + count):
        pub = _child_pubkey_bytes(extpub, branch, i)
        addrs.append(P2TRAddrEncoder.EncodeKey(pub, hrp=hrp))
    return addrs


def _derive_p2pkh(extpub, count, branch, start_index, net):
    ver = (
        CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver")
        if net == "mainnet"
        else CoinsConf.BitcoinTestNet.ParamByKey("p2pkh_net_ver")
    )
    addrs = []
    for i in range(start_index, start_index + count):
        pub = _child_pubkey_bytes(extpub, branch, i)
        addrs.append(P2PKHAddrEncoder.EncodeKey(pub, net_ver=ver))
    return addrs


def _derive_p2sh_p2wpkh(extpub, count, branch, start_index, net):
    ver = (
        CoinsConf.BitcoinMainNet.ParamByKey("p2sh_net_ver")
        if net == "mainnet"
        else CoinsConf.BitcoinTestNet.ParamByKey("p2sh_net_ver")
    )
    addrs = []
    for i in range(start_index, start_index + count):
        pub = _child_pubkey_bytes(extpub, branch, i)
        addrs.append(P2SHAddrEncoder.EncodeKey(pub, net_ver=ver))
    return addrs


def derive_addresses(parsed, count, branch, start_index=0):
    """Derive `count` addresses starting at `start_index` for any supported dtype."""
    extpub = parsed["extpub"]
    net    = xpub_net_and_key(extpub)
    dtype  = parsed["dtype"]

    if dtype == "wpkh":
        return _derive_p2wpkh(extpub, count, branch, start_index, net)
    if dtype == "tr":
        return _derive_p2tr(extpub, count, branch, start_index, net)
    if dtype == "pkh":
        return _derive_p2pkh(extpub, count, branch, start_index, net)
    if dtype == "sh(wpkh)":
        return _derive_p2sh_p2wpkh(extpub, count, branch, start_index, net)
    raise ValueError(f"Unknown dtype: {dtype}")


def derive_wpkh_addresses(extpub, count, branch, start_index=0):
    net = xpub_net_and_key(extpub)
    return _derive_p2wpkh(extpub, count, branch, start_index, net)


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
        self._input_cache: dict[str, list[dict]] = {}
        self._output_cache: dict[str, list[dict]] = {}

    def fetch_tx(self, txid):
        return self.tx_map.get(txid)

    def is_ours(self, address):
        return address in self.our_addrs

    def address_role(self, address, txid=None):
        if address not in self.our_addrs:
            return "external"
        meta = self.addr_map.get(address, {})
        if meta.get("internal"):
            return "change"
        return "receive"

    def input_participants(self, txid):
        cached = self._input_cache.get(txid)
        if cached is not None:
            return cached
        tx = self.fetch_tx(txid)
        if not tx:
            self._input_cache[txid] = []
            return []
        result = []
        for vin in tx.get("vin", []):
            if vin.get("is_coinbase"):
                result.append({
                    "address": "",
                    "value": 0,
                    "value_sats": 0,
                    "txid": "",
                    "vout": 0,
                    "role": "coinbase",
                    "script_type": "coinbase",
                    "ours": False,
                })
                continue
            prev = vin.get("prevout") or {}
            addr = prev.get("scriptpubkey_address", "")
            sats = prev.get("value", 0)
            result.append({
                "address": addr,
                "value": sats / 100_000_000,
                "value_sats": sats,
                "txid": vin.get("txid", ""),
                "vout": vin.get("vout", 0),
                "role": self.address_role(addr, txid),
                "script_type": self.get_script_type(addr) if addr else "unknown",
                "ours": self.is_ours(addr),
            })
        self._input_cache[txid] = result
        return result

    def output_participants(self, txid):
        cached = self._output_cache.get(txid)
        if cached is not None:
            return cached
        tx = self.fetch_tx(txid)
        if not tx:
            self._output_cache[txid] = []
            return []
        result = []
        for vout in tx.get("vout", []):
            addr = vout.get("scriptpubkey_address", "")
            sats = vout.get("value", 0)
            st = vout.get("scriptpubkey_type", "unknown")
            result.append({
                "address": addr,
                "value": sats / 100_000_000,
                "value_sats": sats,
                "n": vout.get("n", 0),
                "script_type": st,
                "type": st,
                "role": self.address_role(addr, txid),
                "ours": self.is_ours(addr),
            })
        self._output_cache[txid] = result
        return result

    @cached_property
    def our_send_txids(self):
        result = []
        for txid in self.our_txids:
            participants = self.input_participants(txid)
            if any(p["ours"] for p in participants):
                result.append(txid)
        return result

    @cached_property
    def our_receive_txids(self):
        result = []
        for txid in self.our_txids:
            inputs = self.input_participants(txid)
            outputs = self.output_participants(txid)
            if not any(p["ours"] for p in inputs) and any(p["ours"] for p in outputs):
                result.append(txid)
        return result

    def get_input_addresses(self, txid):
        return self.input_participants(txid)

    def get_output_addresses(self, txid):
        return self.output_participants(txid)

    def get_script_type(self, address):
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
# DETECTORS  (all accept cfg: ScanConfig as last param)
# ─────────────────────────────────────────────────────────

def detect_address_reuse(g, cfg: ScanConfig):
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
                    f"Address {addr[:12]}… reused: received funds in "
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


def detect_dust(g, cfg: ScanConfig):
    findings = []
    reported = set()

    current_unspent_txids = {(u["address"], u["txid"], u["vout"]) for u in g.utxos}
    for u in g.utxos:
        sats = satoshis(u["amount"])
        if sats <= cfg.dust_sats and g.is_ours(u.get("address", "")):
            key = (u["address"], u["txid"], u["vout"])
            reported.add(key)
            severity = "HIGH" if sats <= cfg.strict_dust_sats else "MEDIUM"
            findings.append({
                "type": "DUST",
                "severity": severity,
                "description": (
                    f"Unspent dust UTXO at {u['address'][:12]}… "
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
            if sats <= cfg.dust_sats and key not in reported and key not in current_unspent_txids:
                reported.add(key)
                findings.append({
                    "type": "DUST",
                    "severity": "LOW",
                    "description": (
                        f"Historical dust output at {addr[:12]}… "
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


def detect_dust_spending(g, cfg: ScanConfig):
    findings = []

    for txid in g.our_txids:
        inputs = g.input_participants(txid)
        if not inputs or len(inputs) < 2:
            continue

        dust_inputs = []
        normal_inputs = []
        for p in inputs:
            if not p["ours"]:
                continue
            sats = satoshis(p["value"])
            if sats <= cfg.dust_sats:
                dust_inputs.append(p)
            elif sats > cfg.normal_input_min_sats:
                normal_inputs.append(p)

        if dust_inputs and normal_inputs:
            findings.append({
                "type": "DUST_SPENDING",
                "severity": "HIGH",
                "description": (
                    f"TX {txid[:16]}… spends {len(dust_inputs)} dust input(s) alongside "
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


def detect_cioh(g, cfg: ScanConfig):
    findings = []
    for txid in g.our_txids:
        inputs = g.input_participants(txid)
        if len(inputs) < 2:
            continue
        our_inputs = [p for p in inputs if p["ours"]]
        if len(our_inputs) >= 2:
            n_ours = len(our_inputs)
            total = len(inputs)
            ownership_pct = round(n_ours / total * 100)
            severity = "CRITICAL" if n_ours == total else "HIGH"
            findings.append({
                "type": "CIOH",
                "severity": severity,
                "description": f"TX {txid[:16]}… merges {n_ours}/{total} of your inputs ({ownership_pct}% ownership).",
                "details": {
                    "txid": txid,
                    "our_inputs": n_ours,
                    "total_inputs": total,
                    "ownership_pct": ownership_pct,
                    "our_input_addresses": [p["address"] for p in our_inputs][:5],
                },
                "correction": "Use coin control to avoid merging multiple UTXOs in a single transaction. If consolidation is unavoidable, do it via CoinJoin.",
            })
    return findings


def detect_change_detection(g, cfg: ScanConfig):
    findings = []

    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue
        outputs = g.output_participants(txid)
        inputs = g.input_participants(txid)
        if not outputs or len(outputs) < 2:
            continue

        our_in = [p for p in inputs if p["ours"]]
        if not our_in:
            continue

        our_outs = [p for p in outputs if p["ours"]]
        ext_outs = [p for p in outputs if not p["ours"]
                    and p.get("script_type") != "op_return"]

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

                in_types = {p["script_type"] for p in our_in}
                ch_type = g.get_script_type(change["address"])
                pay_type = g.get_script_type(payment["address"])
                if ch_type in in_types and ch_type != pay_type:
                    problems.append(
                        f"Change script type ({ch_type}) matches input but differs from payment ({pay_type})"
                    )

            if change["role"] == "change":
                if "BIP-44 internal path" not in " ".join(problems):
                    problems.append(
                        "Change uses an internal (BIP-44 /1/*) derivation path — standard wallet change pattern"
                    )

        if problems:
            findings.append({
                "type": "CHANGE_DETECTION",
                "severity": "MEDIUM",
                "description": (
                    f"TX {txid[:16]}… has identifiable change output(s) "
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


def detect_consolidation(g, cfg: ScanConfig):
    findings = []
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
        if n_in >= cfg.consolidation_min_inputs and n_out <= cfg.consolidation_max_outputs:
            seen_txids.add(parent_txid)
            parent_inputs = g.input_participants(parent_txid)
            our_parent_in = [p for p in parent_inputs if p["ours"]]
            findings.append({
                "type": "CONSOLIDATION",
                "severity": "MEDIUM",
                "description": (
                    f"UTXO {parent_txid[:16]}…:{utxo['vout']} "
                    f"({utxo['amount']:.8f} BTC) born from a {n_in}-input consolidation."
                ),
                "details": {
                    "txid": parent_txid,
                    "vout": utxo["vout"],
                    "amount_btc": round(utxo["amount"], 8),
                    "consolidation_inputs": n_in,
                    "consolidation_outputs": n_out,
                    "our_inputs_in_consolidation": len(our_parent_in),
                },
                "correction": (
                    "Avoid consolidating many UTXOs in a single transaction — it permanently links all those "
                    "addresses under CIOH. If fee savings require consolidation, do it through a CoinJoin "
                    "(e.g., Whirlpool or JoinMarket) so the link is indistinguishable from other participants."
                ),
            })

    return findings


def detect_script_type_mixing(g, cfg: ScanConfig):
    findings = []

    for txid in g.our_txids:
        inputs = g.input_participants(txid)
        if len(inputs) < 2:
            continue

        our_in = [p for p in inputs if p["ours"]]
        if len(our_in) < 2:
            continue

        types = {p["script_type"] for p in inputs}
        types.discard("unknown")

        if len(types) >= 2:
            findings.append({
                "type": "SCRIPT_TYPE_MIXING",
                "severity": "HIGH",
                "description": (
                    f"TX {txid[:16]}… mixes input script types: {sorted(types)}. "
                    "Each type combination is a rare fingerprint."
                ),
                "details": {
                    "txid": txid,
                    "script_types": sorted(types),
                    "inputs": [
                        {
                            "address": p["address"],
                            "script_type": p["script_type"],
                            "ours": p["ours"],
                        }
                        for p in inputs
                    ],
                },
                "correction": (
                    "Migrate all funds to a single address type — preferably Taproot (P2TR / bc1p). "
                    "Never mix P2PKH, P2SH-P2WPKH, P2WPKH, and P2TR inputs in the same transaction. "
                    "Sweep legacy UTXOs to a fresh Taproot wallet through a CoinJoin to avoid the cross-type link."
                ),
            })

    return findings


def detect_cluster_merge(g, cfg: ScanConfig):
    findings = []

    for txid in g.our_txids:
        inputs = g.input_participants(txid)
        if len(inputs) < 2:
            continue

        our_in = [p for p in inputs if p["ours"]]
        if len(our_in) < 2:
            continue

        funding_sources = {}
        for p in our_in:
            parent = g.fetch_tx(p["txid"])
            if not parent:
                continue
            gp_sources = set()
            for p_vin in parent.get("vin", []):
                if p_vin.get("coinbase"):
                    gp_sources.add("coinbase")
                else:
                    src = p_vin.get("txid", "")
                    if src:
                        gp_sources.add(src[:16])
            if gp_sources:
                funding_sources[f"{p['txid'][:16]}:{p['vout']}"] = gp_sources

        all_sources = list(funding_sources.values())
        if len(all_sources) >= 2:
            merged_clusters = any(
                all_sources[i].isdisjoint(all_sources[j])
                for i in range(len(all_sources))
                for j in range(i + 1, len(all_sources))
            )
            if merged_clusters:
                findings.append({
                    "type": "CLUSTER_MERGE",
                    "severity": "HIGH",
                    "description": (
                        f"TX {txid[:16]}… merges UTXOs from "
                        f"{len(funding_sources)} different funding chains."
                    ),
                    "details": {
                        "txid": txid,
                        "funding_sources": {k: sorted(v) for k, v in funding_sources.items()},
                    },
                    "correction": (
                        "Use coin control to spend UTXOs from only one funding source per transaction. "
                        "Keep UTXOs received from different counterparties in separate wallets or accounts. "
                        "If you must merge UTXOs from different origins, pass them through a CoinJoin first."
                    ),
                })

    return findings


def detect_utxo_age_spread(g, cfg: ScanConfig):
    findings = []

    our_utxos = [u for u in g.utxos if g.is_ours(u.get("address", ""))]
    if len(our_utxos) < 2:
        return findings

    aged = [u for u in our_utxos if u.get("blockheight", 0) > 0]
    if len(aged) < 2:
        return findings

    aged.sort(key=lambda x: x["blockheight"])
    oldest = aged[0]
    newest = aged[-1]
    spread = newest["blockheight"] - oldest["blockheight"]

    if spread < cfg.utxo_age_spread_blocks:
        return findings

    findings.append({
        "type": "UTXO_AGE_SPREAD",
        "severity": "LOW",
        "description": (
            f"UTXO age spread of {spread:,} blocks between oldest "
            f"(block {oldest['blockheight']:,}) and newest (block {newest['blockheight']:,})."
        ),
        "details": {
            "spread_blocks": spread,
            "oldest": {
                "txid": oldest["txid"],
                "blockheight": oldest["blockheight"],
                "amount_btc": round(oldest["amount"], 8),
            },
            "newest": {
                "txid": newest["txid"],
                "blockheight": newest["blockheight"],
                "amount_btc": round(newest["amount"], 8),
            },
        },
        "correction": (
            "Prefer spending older UTXOs first (FIFO coin selection) to normalize the age distribution. "
            "Route very old UTXOs through a CoinJoin to reset their history before spending. "
            "Avoid holding long-dormant coins in the same wallet as freshly received funds."
        ),
    })

    old_utxos = [u for u in aged if (newest["blockheight"] - u["blockheight"]) >= cfg.dormant_utxo_blocks]
    if old_utxos:
        findings.append({
            "type": "DORMANT_UTXOS",
            "severity": "LOW",
            "description": (
                f"{len(old_utxos)} UTXO(s) are significantly older than the newest "
                f"(>= {cfg.dormant_utxo_blocks} blocks gap) — dormant/hoarded coin pattern."
            ),
            "details": {
                "count": len(old_utxos),
                "threshold_blocks": cfg.dormant_utxo_blocks,
                "utxos": [
                    {"txid": u["txid"], "blockheight": u["blockheight"], "amount_btc": round(u["amount"], 8)}
                    for u in old_utxos[:5]
                ],
            },
            "correction": (
                "Avoid leaving very old coins as obvious dormancy markers. "
                "Route them through a CoinJoin to reset history, or spend with FIFO coin selection."
            ),
        })

    return findings


def detect_exchange_origin(g, cfg: ScanConfig):
    findings = []

    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue

        outputs = g.output_participants(txid)
        n_out = len(outputs)
        if n_out < cfg.exchange_batch_outputs:
            continue

        inputs = g.input_participants(txid)
        our_inputs = [p for p in inputs if p["ours"]]
        our_outputs = [p for p in outputs if p["ours"]]

        if our_inputs:
            continue
        if not our_outputs:
            continue

        signals = []
        signals.append(f"High output count: {n_out}")

        unique_addrs = {p["address"] for p in outputs if p["address"]}
        if len(unique_addrs) >= cfg.exchange_batch_outputs:
            signals.append(f"{len(unique_addrs)} unique recipient addresses")

        input_total = sum(p["value"] for p in inputs)
        output_vals = sorted(p["value"] for p in outputs)
        if output_vals:
            median_out = output_vals[len(output_vals) // 2]
            if median_out > 0:
                ratio = input_total / median_out
                if ratio > 10:
                    signals.append(f"Input/median-output ratio: {ratio:.0f}x (hot wallet pattern)")

        if len(signals) >= 2:
            findings.append({
                "type": "EXCHANGE_ORIGIN",
                "severity": "MEDIUM",
                "description": (
                    f"TX {txid[:16]}… looks like an exchange batch withdrawal "
                    f"({len(signals)} signal(s) matched)."
                ),
                "details": {
                    "txid": txid,
                    "signals": signals,
                    "received_outputs": [
                        {"address": o["address"], "amount_btc": round(o["value"], 8)}
                        for o in our_outputs
                    ],
                },
                "correction": (
                    "Withdraw via Lightning Network instead of on-chain to avoid the exchange-origin fingerprint. "
                    "If on-chain withdrawal is required, pass the UTXO through a CoinJoin before using it for "
                    "other payments so the exchange link is severed from your subsequent spending history."
                ),
            })

    return findings


def detect_tainted_utxo_merge(g, cfg: ScanConfig):
    findings = []
    warnings = []

    exchange_txids = set()
    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue
        outputs = g.output_participants(txid)
        if len(outputs) < cfg.exchange_batch_outputs:
            continue
        inputs = g.input_participants(txid)
        if any(p["ours"] for p in inputs):
            continue
        if any(p["ours"] for p in outputs):
            exchange_txids.add(txid)

    if not exchange_txids:
        return findings, warnings

    for txid in g.our_txids:
        inputs = g.input_participants(txid)
        if len(inputs) < 2:
            continue

        our_in = [p for p in inputs if p["ours"]]
        if len(our_in) < 2:
            continue

        tainted = [p for p in our_in if p["txid"] in exchange_txids]
        clean = [p for p in our_in if p["txid"] not in exchange_txids]

        if tainted and clean:
            findings.append({
                "type": "TAINTED_UTXO_MERGE",
                "severity": "HIGH",
                "description": (
                    f"TX {txid[:16]}… mixes {len(tainted)} exchange-origin (KYC-tainted) "
                    f"input(s) with {len(clean)} unrelated input(s) — links your identity to all inputs."
                ),
                "details": {
                    "txid": txid,
                    "tainted_inputs": [
                        {"address": p["address"], "from_exchange_tx": p["txid"][:16]}
                        for p in tainted
                    ],
                    "clean_inputs": [
                        {"address": p["address"], "amount_btc": round(p["value"], 8)}
                        for p in clean
                    ],
                },
                "correction": (
                    "Never merge exchange-origin UTXOs with unrelated UTXOs. "
                    "First pass the exchange UTXO through a CoinJoin (Whirlpool, JoinMarket) to break the KYC link, "
                    "then spend the mixed output separately."
                ),
            })

    already_merged_txids = {f.get("details", {}).get("txid", "") for f in findings}
    unspent_txids = {u["txid"] for u in g.utxos if g.is_ours(u.get("address", ""))}

    for ex_txid in exchange_txids:
        if ex_txid not in unspent_txids:
            continue
        if ex_txid in already_merged_txids:
            continue

        our_outputs = [p for p in g.output_participants(ex_txid) if p["ours"]]
        if not our_outputs:
            continue

        warnings.append({
            "type": "DIRECT_TAINT",
            "severity": "HIGH",
            "description": (
                f"TX {ex_txid[:16]}… is directly from a known exchange-origin source. "
                "The received UTXO(s) are KYC-tainted and still unspent — "
                "do not merge with other UTXOs without CoinJoin first."
            ),
            "details": {
                "txid": ex_txid,
                "received_outputs": [
                    {"address": p["address"], "amount_btc": round(p["value"], 8)}
                    for p in our_outputs
                ],
            },
            "correction": (
                "Pass this UTXO through a CoinJoin (Whirlpool, JoinMarket) before spending. "
                "Never merge it with funds from other sources — doing so will link your exchange "
                "identity to your entire spending history."
            ),
        })

    return findings, warnings


def detect_behavioral_fingerprint(g, cfg: ScanConfig):
    findings = []

    send_txids = g.our_send_txids

    if len(send_txids) < cfg.min_send_txs_for_behavioral:
        return findings

    output_counts = []
    payment_amounts_sats = []
    input_script_types = []
    rbf_signals = []
    locktime_values = []
    fee_rates = []
    n_inputs_list = []
    uses_round_amounts = 0
    total_payments = 0
    change_address_types_used = set()
    payment_address_types_used = set()

    for txid in send_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue

        vins = tx.get("vin", [])
        vouts = tx.get("vout", [])
        n_inputs_list.append(len(vins))
        output_counts.append(len(vouts))
        locktime_values.append(tx.get("locktime", 0))

        for vin in vins:
            seq = vin.get("sequence", 0xffffffff)
            rbf_signals.append(seq < 0xfffffffe)

        for p in g.input_participants(txid):
            if p["ours"]:
                input_script_types.append(p["script_type"])

        for p in g.output_participants(txid):
            sats = satoshis(p["value"])
            if p["ours"]:
                change_address_types_used.add(p["script_type"])
            else:
                payment_amounts_sats.append(sats)
                payment_address_types_used.add(p["script_type"])
                total_payments += 1
                if sats > 0 and (sats % 100_000 == 0 or sats % 1_000_000 == 0):
                    uses_round_amounts += 1

        fee = tx.get("fee", 0)
        weight = tx.get("weight", 0)
        vsize = max(1, (weight + 3) // 4) if weight else 0
        if vsize > 0 and fee > 0:
            fee_rates.append(fee / vsize)

    problems = []

    if total_payments > 0:
        round_pct = uses_round_amounts / total_payments * 100
        if round_pct > cfg.round_payment_pct_threshold:
            problems.append(
                f"Round payment amounts: {round_pct:.0f}% of payments are round numbers — "
                "a distinctive behavioral pattern that aids clustering."
            )

    if output_counts and all(c == output_counts[0] for c in output_counts) and len(output_counts) >= 3:
        problems.append(
            f"Uniform output count: all {len(output_counts)} send TXs have exactly "
            f"{output_counts[0]} outputs — consistent structure aids fingerprinting."
        )

    input_types_set = set(input_script_types)
    if len(input_types_set) > 1:
        problems.append(
            f"Mixed input script types across TXs: {input_types_set} — "
            "mixing address families is rare and highly identifying."
        )
    elif "p2pkh" in input_types_set:
        problems.append(
            "All inputs use legacy P2PKH — uncommon today. "
            "This alone narrows your anonymity set significantly."
        )

    if rbf_signals:
        rbf_pct = sum(rbf_signals) / len(rbf_signals) * 100
        if rbf_pct == 100:
            problems.append(
                "RBF always enabled: 100% of inputs signal replace-by-fee — "
                "distinguishing feature vs non-RBF wallets."
            )
        elif rbf_pct == 0:
            problems.append(
                "RBF never enabled: 0% of inputs signal replace-by-fee — "
                "uncommon in modern wallets, distinguishes your software."
            )

    if locktime_values and len(locktime_values) >= 3:
        nonzero_lt = [lt for lt in locktime_values if lt > 0]
        if len(nonzero_lt) == len(locktime_values):
            problems.append(
                "Anti-fee-sniping locktime always set — consistent with Bitcoin Core / Electrum. "
                "Reveals your wallet software."
            )
        elif not nonzero_lt:
            problems.append(
                "Locktime always 0 — no anti-fee-sniping. "
                "Distinguishes your wallet from Bitcoin Core / Electrum defaults."
            )

    if len(fee_rates) >= 3:
        avg_fee = sum(fee_rates) / len(fee_rates)
        if avg_fee > 0:
            variance = sum((f - avg_fee) ** 2 for f in fee_rates) / len(fee_rates)
            stddev = variance ** 0.5
            cv = stddev / avg_fee
            if cv < cfg.fee_rate_cv_threshold:
                problems.append(
                    f"Very consistent fee rate: avg {avg_fee:.1f} sat/vB ± {stddev:.1f} "
                    f"(CV={cv:.2f}) — low variance suggests fixed-fee-rate wallet configuration."
                )

    if change_address_types_used and payment_address_types_used:
        if change_address_types_used != payment_address_types_used:
            problems.append(
                f"Change uses different script type ({change_address_types_used}) than "
                f"payments ({payment_address_types_used}) — trivially identifies change outputs."
            )

    if n_inputs_list and len(n_inputs_list) >= 3:
        if all(n == n_inputs_list[0] for n in n_inputs_list) and n_inputs_list[0] > 1:
            problems.append(
                f"Always uses exactly {n_inputs_list[0]} inputs per TX — unusual and identifying."
            )

    if problems:
        findings.append({
            "type": "BEHAVIORAL_FINGERPRINT",
            "severity": "MEDIUM",
            "description": (
                f"Behavioral fingerprint detected across {len(send_txids)} send transactions "
                f"({len(problems)} pattern(s))."
            ),
            "details": {
                "send_tx_count": len(send_txids),
                "patterns": problems,
            },
            "correction": (
                "Switch to wallet software that applies anti-fingerprinting defaults: anti-fee-sniping locktime, "
                "randomized fee rates, and RBF enabled by default. "
                "Avoid sending only round amounts — add small random satoshi offsets to payment values. "
                "Standardize on Taproot so your input-type set is not distinctive."
            ),
        })

    return findings


def detect_payjoin_interaction(g, cfg: ScanConfig):
    findings = []
    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue
        inputs = g.input_participants(txid)
        if len(inputs) < 2:
            continue

        our_input_addrs = [p["address"] for p in inputs if p["ours"]]
        ext_input_addrs = [p["address"] for p in inputs if not p["ours"] and p["address"]]

        if not our_input_addrs or not ext_input_addrs:
            continue

        outputs = g.output_participants(txid)
        our_output_addrs = [p["address"] for p in outputs if p["ours"]]

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


def detect_whirlpool_patterns(g, cfg: ScanConfig):
    findings = []
    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue

        outputs = g.output_participants(txid)
        if len(outputs) < 4:
            continue

        output_values = [p["value_sats"] for p in outputs]

        for pool_sats in WHIRLPOOL_POOL_AMOUNTS:
            matching = [v for v in output_values if v == pool_sats]
            if len(matching) >= 4:
                our_outputs = [p for p in outputs if p["value_sats"] == pool_sats and p["ours"]]
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
                    break
    return findings


def detect_fee_fingerprinting(g, cfg: ScanConfig):
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

        if vsize > 0 and fee > 0:
            fee_rate = round(fee / vsize)
            if fee_rate in round_fee_rates:
                round_fee_txids.append({
                    "txid": txid,
                    "fee_rate_sat_vb": fee_rate,
                    "fee_sats": fee,
                })

        outputs = g.output_participants(txid)
        external_outputs = [
            p for p in outputs
            if not p["ours"] and p["script_type"] != "op_return"
        ]
        if len(external_outputs) >= 5:
            batch_payment_txids.append({
                "txid": txid,
                "external_output_count": len(external_outputs),
            })

        our_outputs = [p for p in outputs if p["ours"]]
        non_our_outputs = [
            p for p in outputs
            if not p["ours"] and p["script_type"] != "op_return"
        ]
        if our_outputs and non_our_outputs:
            our_max = max(p["value_sats"] for p in our_outputs)
            ext_max = max(p["value_sats"] for p in non_our_outputs)
            if ext_max > 0 and our_max / ext_max < cfg.tiny_change_ratio and our_max < cfg.tiny_change_max_sats:
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
                "transactions": round_fee_txids[:10],
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


def build_addr_map(addresses, branch, start_index=0, script_type="p2wpkh"):
    addr_map = {}
    for i, addr in enumerate(addresses, start=start_index):
        addr_map[addr] = {
            "type": script_type,
            "internal": branch == 1,
            "index": i,
        }
    return addr_map


SEVERITY_PENALTY = {
    "CRITICAL": 20,
    "HIGH": 12,
    "MEDIUM": 6,
    "LOW": 2,
    "INFO": 1,
}

WARNING_PENALTY = {
    "CRITICAL": 8,
    "HIGH": 5,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 0,
}

GRADE_THRESHOLDS = [
    (90, "A", "Excellent privacy practices"),
    (70, "B", "Good — minor issues detected"),
    (50, "C", "Fair — some privacy risks"),
    (30, "D", "Poor — significant exposure"),
    (0,  "F", "Critical — immediate action needed"),
]


def compute_privacy_score(findings, warnings):
    deductions = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        deductions += SEVERITY_PENALTY.get(sev, 1)

    for w in warnings:
        sev = w.get("severity", "LOW")
        deductions += WARNING_PENALTY.get(sev, 1)

    score = max(0, 100 - deductions)

    grade = "F"
    label = "Critical — immediate action needed"
    for threshold, g, l in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = g
            label = l
            break

    return {
        "score": score,
        "grade": grade,
        "label": label,
        "deductions": deductions,
        "severity_breakdown": severity_counts,
    }


def scan_branch(parsed, offset, count, branch, cfg: ScanConfig = None):
    global _scan_start_offset
    _scan_start_offset = offset

    if cfg is None:
        cfg = DEFAULT_CONFIG

    addresses = derive_addresses(parsed, count, branch, start_index=offset)
    addr_map = build_addr_map(addresses, branch, start_index=offset, script_type=parsed["script_type"])
    tx_map, addr_txs, utxos, active_addresses, addr_received_outputs = collect_wallet_data(addresses)
    graph = TxGraph(addr_map, tx_map, addr_txs, utxos, addr_received_outputs)

    findings = []
    warnings = []

    # Each detector call is guarded by cfg.is_enabled()
    if cfg.is_enabled("address_reuse"):
        findings.extend(detect_address_reuse(graph, cfg))
    if cfg.is_enabled("dust"):
        findings.extend(detect_dust(graph, cfg))
    if cfg.is_enabled("dust_spending"):
        findings.extend(detect_dust_spending(graph, cfg))
    if cfg.is_enabled("cioh"):
        findings.extend(detect_cioh(graph, cfg))
    if cfg.is_enabled("payjoin_interaction"):
        findings.extend(detect_payjoin_interaction(graph, cfg))
    if cfg.is_enabled("whirlpool_patterns"):
        findings.extend(detect_whirlpool_patterns(graph, cfg))
    if cfg.is_enabled("fee_fingerprinting"):
        findings.extend(detect_fee_fingerprinting(graph, cfg))
    if cfg.is_enabled("change_detection"):
        findings.extend(detect_change_detection(graph, cfg))
    if cfg.is_enabled("consolidation"):
        findings.extend(detect_consolidation(graph, cfg))
    if cfg.is_enabled("script_type_mixing"):
        findings.extend(detect_script_type_mixing(graph, cfg))
    if cfg.is_enabled("cluster_merge"):
        findings.extend(detect_cluster_merge(graph, cfg))

    if cfg.is_enabled("tainted_utxo_merge"):
        taint_findings, taint_warnings = detect_tainted_utxo_merge(graph, cfg)
        findings.extend(taint_findings)
        warnings.extend(taint_warnings)

    if cfg.is_enabled("exchange_origin"):
        findings.extend(detect_exchange_origin(graph, cfg))
    if cfg.is_enabled("behavioral_fingerprint"):
        findings.extend(detect_behavioral_fingerprint(graph, cfg))

    age_findings = detect_utxo_age_spread(graph, cfg) if cfg.is_enabled("utxo_age_spread") else []
    for f in age_findings:
        if f["type"] == "DORMANT_UTXOS":
            warnings.append(f)
        else:
            findings.append(f)

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
            "privacy_score": compute_privacy_score(findings, warnings),
        },
        "_active_addresses": active_addresses,
    }


def _merge_branch_reports(reports):
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

        for warning in r["warnings"]:
            txid = warning.get("txid") or (warning.get("details") or {}).get("txid", "")
            addr = warning.get("address") or (warning.get("details") or {}).get("address", "")
            key = f"{warning['type']}::{addr}::{txid}::{warning.get('description', '')}"
            if key not in seen_finding_keys:
                seen_finding_keys.add(key)
                all_warnings.append(warning)

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
            "privacy_score": compute_privacy_score(all_findings, all_warnings),
        },
        "aggregate_scan_window": {
            "from_index": from_index or 0,
            "to_index": to_index or 0,
        },
    }


def run_auto_scan(descriptor, branch_mode="receive", cfg: ScanConfig = None):
    global _request_count
    _request_count = 0

    if cfg is None:
        cfg = DEFAULT_CONFIG

    parsed = parse_descriptor(descriptor)

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
            report = scan_branch(parsed, offset, AUTO_BATCH_SIZE, branch, cfg)
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
        "proxy": session.proxies.get("https", None),
        "enabled_detectors": sorted(cfg.enabled_detectors) if cfg.enabled_detectors is not None else "all",
    }
    final["scan_window"] = {
        "from_index": final["aggregate_scan_window"]["from_index"],
        "to_index": final["aggregate_scan_window"]["to_index"],
        "branch": branches_to_scan[0] if len(branches_to_scan) == 1 else -1,
        "offset": 0,
        "count": total_addresses_scanned,
    }
    return final


def run_scan(descriptor, offset=0, count=60, branch_mode="receive", cfg: ScanConfig = None):
    global _request_count
    _request_count = 0

    if cfg is None:
        cfg = DEFAULT_CONFIG

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
        report = scan_branch(parsed, offset, count, branch, cfg)

        if (
            branch == 0
            and branch_mode == "receive"
            and report["stats"]["active_addresses"] == 0
            and report["stats"]["transactions_analyzed"] == 0
        ):
            fallback = scan_branch(parsed, offset, count, 1, cfg)
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
            "proxy": session.proxies.get("https", None),
            "enabled_detectors": sorted(cfg.enabled_detectors) if cfg.enabled_detectors is not None else "all",
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
        "proxy": session.proxies.get("https", None),
        "enabled_detectors": sorted(cfg.enabled_detectors) if cfg.enabled_detectors is not None else "all",
    }
    return merged
