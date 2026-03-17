#!/usr/bin/env python3
import base58
import sys
import re
import json
from collections import defaultdict

import requests
from bip_utils import Bip32Secp256k1, P2WPKHAddrEncoder, CoinsConf


API_BASE = "https://blockstream.info/api"


def fail(msg, code=1):
    print(msg, file=sys.stderr)
    sys.exit(code)


def satoshis(btc):
    return int(round(float(btc) * 100_000_000))


def parse_descriptor(descriptor):
    desc = descriptor.strip()
    desc = desc.split("#")[0]

    m = re.fullmatch(r"wpkh\(\[([0-9a-fA-F]{8})(/[^\]]+)?\]([A-Za-z0-9]+)/(0|1)/\*\)", desc)
    if not m:
        raise ValueError("Only descriptors of the form wpkh([fingerprint/path]xpub.../0/*) or /1/* are supported")

    fingerprint = m.group(1).lower()
    origin_path = (m.group(2) or "").lstrip("/")
    extpub = m.group(3)
    branch = int(m.group(4))

    return {
        "fingerprint": fingerprint,
        "origin_path": origin_path,
        "extpub": extpub,
        "branch": branch,
        "descriptor": desc,
    }


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


def convert_slip132_to_bip32(extpub):
    prefix = extpub[:4]
    if prefix not in SLIP132_TO_BIP32:
        raise ValueError(f"Unsupported extended pub prefix: {prefix}")

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


def derive_wpkh_addresses(extpub, count, branch):
    net = xpub_net_and_key(extpub)
    bip32_key = convert_slip132_to_bip32(extpub)
    account_ctx = Bip32Secp256k1.FromExtendedKey(bip32_key)
    branch_ctx = account_ctx.ChildKey(branch)

    addrs = []
    for i in range(count):
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
    url = f"{API_BASE}{path}"
    r = requests.get(url, timeout=(5, 10))
    r.raise_for_status()
    return r.json()


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


def normalize_script_type(scriptpubkey_type):
    mapping = {
        "v0_p2wpkh": "p2wpkh",
        "p2wpkh": "p2wpkh",
        "v1_p2tr": "p2tr",
        "p2tr": "p2tr",
        "p2sh": "p2sh-p2wpkh",
        "p2pkh": "p2pkh",
    }
    return mapping.get(scriptpubkey_type, scriptpubkey_type or "unknown")


def collect_wallet_data(addresses):
    tx_map = {}
    addr_txs = defaultdict(list)
    utxos = []

    for addr in addresses:
        try:
            txs = address_txs(addr)
        except Exception:
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

    addr_utxos = []

    return tx_map, addr_txs, utxos


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

    def get_script_type(self, address):
        meta = self.addr_map.get(address)
        if meta:
            return meta["type"]
        return "unknown"

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
        outs = []
        for vout in tx.get("vout", []):
            outs.append({
                "address": vout.get("scriptpubkey_address", ""),
                "value": vout.get("value", 0) / 100_000_000,
                "n": vout.get("n", 0),
                "type": normalize_script_type(vout.get("scriptpubkey_type", "unknown")),
            })
        return outs


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


def detect_consolidation(g):
    findings = []
    for u in g.utxos:
        tx = g.fetch_tx(u["txid"])
        if not tx:
            continue
        n_in = len(tx.get("vin", []))
        n_out = len(tx.get("vout", []))
        if n_in >= 3 and n_out <= 2:
            findings.append({
                "type": "CONSOLIDATION",
                "severity": "MEDIUM",
                "description": f"UTXO {u['txid']}:{u['vout']} born from a {n_in}-input consolidation",
                "details": {
                    "txid": u["txid"],
                    "vout": u["vout"],
                    "amount_btc": round(u["amount"], 8),
                    "consolidation_inputs": n_in,
                    "consolidation_outputs": n_out,
                },
                "correction": "Avoid consolidating many UTXOs into one transaction.",
            })
    return findings


def detect_utxo_age_spread(g):
    our_utxos = [u for u in g.utxos if g.is_ours(u.get("address", ""))]
    if len(our_utxos) < 2:
        return [], []

    confs = sorted([u.get("confirmations", 0) for u in our_utxos])
    spread = confs[-1] - confs[0]

    findings = []
    warnings = []

    if spread >= 10:
        findings.append({
            "type": "UTXO_AGE_SPREAD",
            "severity": "LOW",
            "description": f"UTXO age spread of {spread} confirmation buckets",
            "details": {
                "spread": spread,
            },
            "correction": "Consider more consistent coin selection.",
        })

    old_count = len([u for u in our_utxos if u.get("confirmations", 0) >= 1])
    if old_count:
        warnings.append({
            "type": "DORMANT_UTXOS",
            "severity": "LOW",
            "description": f"{old_count} UTXO(s) appear dormant",
            "details": {
                "count": old_count,
            },
        })

    return findings, warnings


def build_addr_map(addresses, branch):
    addr_map = {}
    for i, addr in enumerate(addresses):
        addr_map[addr] = {
            "type": "p2wpkh",
            "internal": branch == 1,
            "index": i,
        }
    return addr_map


def main():
    if len(sys.argv) < 2:
        fail("descriptor argument required")

    descriptor = sys.argv[1]
    parsed = parse_descriptor(descriptor)

    target = "bc1q5r8m2vut9p0hdzlnrr3razqy99wheejkralstf"
    extpub = parsed["extpub"]
    bip32_key = convert_slip132_to_bip32(extpub)
    net = xpub_net_and_key(extpub)

    def make_addr(ctx):
        pubkey_bytes = ctx.PublicKey().RawCompressed().ToBytes()
        hrp = (
            CoinsConf.BitcoinMainNet.ParamByKey("p2wpkh_hrp")
            if net == "mainnet"
            else CoinsConf.BitcoinTestNet.ParamByKey("p2wpkh_hrp")
        )
        return P2WPKHAddrEncoder.EncodeKey(pubkey_bytes, hrp=hrp)

    root = Bip32Secp256k1.FromExtendedKey(bip32_key)

    candidates = {}

    try:
        candidates["root/0..9"] = [make_addr(root.ChildKey(i)) for i in range(10)]
    except Exception:
        candidates["root/0..9"] = []

    for branch in [0, 1]:
        try:
            branch_ctx = root.ChildKey(branch)
            candidates[f"branch-{branch}/0..9"] = [make_addr(branch_ctx.ChildKey(i)) for i in range(10)]
        except Exception:
            candidates[f"branch-{branch}/0..9"] = []

    report = {
        "debug": {
            "target_address": target,
            "matches": {
                name: (target in addrs)
                for name, addrs in candidates.items()
            },
            "candidates": candidates,
        },
        "stats": {
            "transactions_analyzed": 0,
            "addresses_derived": 0,
            "utxos_found": 0,
        },
        "findings": [],
        "warnings": [],
        "summary": {
            "findings": 0,
            "warnings": 0,
            "clean": True,
        },
    }

    print(json.dumps(report))



if __name__ == "__main__":
    main()
