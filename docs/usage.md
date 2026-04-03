# Stealth — Usage Guide

> **Read-only analysis.** Stealth only uses your **extended public key** (xpub/ypub/zpub). It cannot sign transactions or spend funds.

---

## 1. Find your descriptor or xpub

Depending on your wallet, export one of the following:

### Sparrow Wallet
1. Open the wallet → **Settings** tab → **Script Policy** section.
2. Copy the full descriptor string. It looks like:
   ```
   wpkh([a1b2c3d4/84h/0h/0h]xpub6CatWdi...uw/0/*)
   ```
3. Paste it directly into the Stealth input box.

### BlueWallet
1. Wallet → ⋮ menu → **Export / Backup**.
2. Copy the **xpub** shown.
3. Wrap it manually: `wpkh(xpub.../0/*)`

### Electrum
1. **Wallet → Information** → copy the Master Public Key.
2. If your wallet type is **Native SegWit** (bc1q…): use `wpkh(zpub.../0/*)`
3. If **Legacy** (1…): use `pkh(xpub.../0/*)`
4. If **P2SH-SegWit** (3…): use `sh(wpkh(ypub.../0/*))`

### Trezor / Ledger
Use Sparrow Wallet or Specter Desktop as a watch-only companion — they export full descriptors including the key origin (`[fingerprint/path]`).

---

## 2. Descriptor format explained

A full descriptor looks like this:

```
wpkh([a1b2c3d4/84h/0h/0h]xpub6Catw...uw/0/*)#qwer1234
│    │         │           │            │  │  └─ optional checksum (ignored)
│    │         │           │            │  └──── branch: 0=receive, 1=change
│    │         │           │            └─────── derivation wildcard (*)
│    │         │           └──────────────────── extended public key
│    │         └──────────────────────────────── derivation path
│    └────────────────────────────────────────── key fingerprint (8 hex chars)
└─────────────────────────────────────────────── script type
```

The **branch (`/0/*` or `/1/*`)** in the descriptor is overridden by the **Branch selector** in the UI — you can always switch between Receive, Change, or Both regardless of what the descriptor says.

---

## 3. Supported descriptor types

| Descriptor | Address type | Typical prefix | BIP |
|---|---|---|---|
| `wpkh(xpub…/0/*)` | Native SegWit | `bc1q…` | BIP84 |
| `tr(xpub…/0/*)` | Taproot | `bc1p…` | BIP86 |
| `sh(wpkh(ypub…/0/*))` | P2SH-SegWit (wrapped) | `3…` | BIP49 |
| `pkh(xpub…/0/*)` | Legacy | `1…` | BIP44 |

All four accept the optional `[fingerprint/path]` prefix and an optional `#checksum` suffix.

---

## 4. Scan options

### Branch
- **Receive /0** — scans addresses derived on the external (receiving) chain. Use this first.
- **Change /1** — scans internal (change) addresses, used automatically by wallets for transaction change.
- **Both** — scans both chains in one go. Useful for a complete picture but takes roughly twice as long.

### Auto gap-limit
When enabled, Stealth scans in batches and stops automatically once **20 consecutive addresses** have no activity (the BIP44 standard gap limit). This is the most thorough mode for wallets with many historical transactions. Disable it for a quick scan of recent addresses only.

---

## 5. Understanding the results

Each finding has a **severity** label:

| Severity | Meaning |
|---|---|
| 🔴 CRITICAL | Severe privacy leak — your wallet is almost certainly clustered |
| 🟠 HIGH | Significant leak — a chain-analysis heuristic applies directly |
| 🟡 MEDIUM | Notable pattern — identifiable but less certain |
| 🔵 LOW | Minor signal — unlikely to be used alone |

---

## 6. Finding types explained

### ADDRESS_REUSE
The same address received funds in 2 or more transactions. Every reuse **permanently links** those transactions to the same owner on the public blockchain.

**Fix:** Generate a fresh address for every payment. HD wallets do this by default — never share the same address twice.

---

### CIOH — Common Input Ownership Heuristic
A transaction merged multiple of your addresses as inputs. Chain-analysis tools assume all inputs in a transaction belong to the same wallet, so this **clusters your addresses**.

**Fix:** Use coin control to spend from one address at a time. If consolidation is necessary, use CoinJoin.

---

### DUST / DUST_SPENDING
Your wallet received very small amounts (≤ 1,000 sats). Dust attacks are used by surveillance firms to tag wallets: when you later spend the dust alongside real UTXOs, all your inputs get linked.

**Fix:** Freeze dust UTXOs in your wallet settings. Never include them in a payment transaction.

---

### CHANGE_DETECTION
The change output in a transaction is distinguishable from the payment output — for example, the payment is a round number (0.01 BTC) and the change is irregular (0.00873421 BTC), or the change uses a different address type.

**Fix:** Use PayJoin (BIP-78), or choose UTXOs that cover the exact amount with no change needed.

---

### SCRIPT_TYPE_MIXING
A transaction spent inputs of different script types together (e.g. a legacy `1…` address and a SegWit `bc1q…` address). This combination is rare and acts as a unique fingerprint.

**Fix:** Migrate all funds to a single address type — ideally Taproot (`bc1p…`).

---

### CONSOLIDATION
A UTXO was created by a transaction that swept many inputs (≥ 3) into one output. This permanently links all source addresses under CIOH.

**Fix:** If you must consolidate, do it through a CoinJoin so the grouping is indistinguishable from other participants.

---

### CLUSTER_MERGE
A transaction merged UTXOs that came from different funding chains (different origin transactions). This links previously unrelated histories.

**Fix:** Spend UTXOs from only one source per transaction. Use coin control.

---

### EXCHANGE_ORIGIN
A transaction funding your wallet looks like an exchange batch withdrawal (many outputs, many recipients). Your UTXO is identifiable as coming from a custodial service.

**Fix:** Withdraw via Lightning if possible. On-chain: pass through a CoinJoin before spending.

---

### TAINTED_UTXO_MERGE
A KYC-tainted UTXO (from an exchange withdrawal) was merged with unrelated UTXOs. This links your real identity — known to the exchange — to all those inputs.

**Fix:** Never mix exchange-origin UTXOs with other funds directly. CoinJoin the exchange UTXO first.

---

### BEHAVIORAL_FINGERPRINT
Your transactions share consistent patterns across time: always the same fee rate, same output count, same RBF setting, always round payment amounts. Individually these are weak, but together they uniquely identify your wallet software and habits.

**Fix:** Use wallet software with randomized fee estimation, enable RBF by default, and avoid exclusively round payment amounts.

---

### UTXO_AGE_SPREAD / DORMANT_UTXOS
Your wallet holds UTXOs created at very different block heights. Mixing very old coins with recent ones in a single transaction reveals a distinctive dormancy pattern.

**Fix:** Use FIFO coin selection (spend older UTXOs first). Route very old coins through a CoinJoin before mixing them with recent activity.

---

### WHIRLPOOL_COINJOIN ✅
A transaction matches the Whirlpool CoinJoin pattern (≥ 4 equal outputs). This is **good news** — it means your funds were mixed.

**Note:** Make sure post-mix outputs are spent carefully to preserve the anonymity set.

---

## 7. Privacy score interpretation

The report header shows a summary count of findings and warnings:

- **0 findings** — no known heuristics apply to the scanned window. This is the goal.
- **Warnings only** — low-severity informational signals (e.g. dormant UTXOs). No immediate action needed.
- **1–3 findings** — your wallet has some privacy leaks. Review each finding and apply the suggested correction.
- **4+ findings** — significant clustering risk. Consider migrating to a fresh wallet and using CoinJoin.

---

## 8. Privacy: what Stealth can see

Stealth derives addresses from your xpub and queries the public Esplora/Mempool API. It sees **the same data as any blockchain explorer**. Your xpub is **not stored** — it is used only in-memory during the scan and discarded.

For maximum privacy:
- Run Stealth [locally](../README.md#running-locally) so your xpub never leaves your machine.
- Enable the **Tor proxy** in Settings to route API queries through the Tor network.
