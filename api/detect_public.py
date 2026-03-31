#!/usr/bin/env python3
import base58
import sys
import re
import os
import json
from collections import defaultdict

import requests
from bip_utils import Bip32Secp256k1, P2WPKHAddrEncoder, CoinsConf

_primary = os.environ.get("ESPLORA_API_URL", "https://blockstream.info/api").rstrip("/")
_fallback = os.environ.get("ESPLORA_FALLBACK_URL", "https://mempool.space/api").rstrip("/")
API_BASE = _primary

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

def debug(*args):
    print(*args, file=sys.stderr)

def satoshis(btc):
    return int(round(float(btc) * 100_000_000))

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
    for base in (_primary, _fallback):
        try:
            url = f"{base}{path}"
            r = session.get(url, timeout=(5, 10))
            r.raise_for_status()
            return r.json()
        except Exception as e:
            debug(f"api_get failed on {base}: {e}, trying fallback...")
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
        if sats <= 1000 and g.is_ours(u.get("address", "")):
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
                "correction": "Avoid spending dust with normal inputs.",
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
    addresses = derive_wpkh_addresses(parsed["extpub"], count, branch, start_index=offset)
    addr_map = build_addr_map(addresses, branch, start_index=offset)
    tx_map, addr_txs, utxos, active_addresses = collect_wallet_data(addresses)
    graph = TxGraph(addr_map, tx_map, addr_txs, utxos)

    findings = []
    warnings = []
    findings.extend(detect_address_reuse(graph))
    findings.extend(detect_dust(graph))
    findings.extend(detect_cioh(graph))

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
    }


def run_scan(descriptor: str, offset: int = 0, count: int = 20) -> dict:
    if offset < 0:
        raise ValueError("offset must be >= 0")
    if count <= 0 or count > 500:
        raise ValueError("count must be between 1 and 500")

    parsed = parse_descriptor(descriptor)
    primary_branch = parsed["branch"]
    primary_report = scan_branch(parsed, offset, count, primary_branch)
    branches_checked = [primary_branch]

    should_fallback = (
        primary_branch == 0
        and primary_report["stats"]["active_addresses"] == 0
        and primary_report["stats"]["transactions_analyzed"] == 0
        and primary_report["stats"]["utxos_found"] == 0
    )

    final_report = primary_report

    if should_fallback:
        fallback_report = scan_branch(parsed, offset, count, 1)
        branches_checked.append(1)
        has_activity = (
            fallback_report["stats"]["active_addresses"] > 0
            or fallback_report["stats"]["transactions_analyzed"] > 0
            or fallback_report["stats"]["utxos_found"] > 0
        )
        if has_activity:
            final_report = fallback_report
            final_report["warnings"].append({
                "type": "BRANCH_FALLBACK",
                "severity": "LOW",
                "description": "No activity on branch 0; switched to branch 1.",
                "details": {"requested_branch": 0, "used_branch": 1},
            })
        else:
            primary_report["warnings"].append({
                "type": "NO_ACTIVITY_IN_SCANNED_WINDOW",
                "severity": "LOW",
                "description": "No activity found on branch 0 or branch 1 for this scan window.",
                "details": {"offset": offset, "count": count, "branches_checked": branches_checked},
            })
            final_report = primary_report

    final_report["summary"]["findings"] = len(final_report["findings"])
    final_report["summary"]["warnings"] = len(final_report["warnings"])
    final_report["summary"]["clean"] = (
        len(final_report["findings"]) == 0 and len(final_report["warnings"]) == 0
    )
    final_report["scan_meta"] = {
        "branches_checked": branches_checked,
        "fallback_used": final_report["scan_window"]["branch"] != primary_branch,
        "requested_branch": primary_branch,
        "returned_branch": final_report["scan_window"]["branch"],
        "api_base": API_BASE,
    }

    return final_report
