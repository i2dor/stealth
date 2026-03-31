# Stealth — Bitcoin Wallet Privacy Analyzer

> Analyze the on-chain privacy of any Bitcoin wallet descriptor. Stealth derives addresses from your descriptor, scans transaction history via public blockchain APIs, and returns a structured report of privacy vulnerabilities — with severity ratings, explanations, and actionable remediation steps.

**Live demo:** [stealth.vercel.app](https://stealth-bitcoin.vercel.app)

---

## What it does

Bitcoin transactions are pseudonymous, not anonymous. Every transaction you make leaves fingerprints that can be used to cluster addresses, infer wallet software, link identities, and trace fund flows. Stealth automates the privacy audit process:

1. **You paste a wallet descriptor** (e.g. `wpkh([a1b2c3d4/84h/0h/0h]xpub.../0/*)`) into the UI
2. **Stealth derives Bitcoin addresses** from the descriptor using BIP32 key derivation
3. **It fetches transaction history** for each address from Blockstream or Mempool.space
4. **Multiple heuristic detectors** analyze the transaction graph for privacy leaks
5. **A full report** is returned — findings with severity, descriptions, affected transactions, and how to fix each issue
6. **Export to PDF** — download a formatted report for offline review

All analysis is **read-only**. Stealth never broadcasts transactions or modifies any wallet state.

---

## Supported descriptor formats

| Format | Script type | Prefix |
|---|---|---|
| `wpkh(xpub...)` | Native SegWit (P2WPKH) | `xpub` |
| `wpkh(zpub...)` | Native SegWit (P2WPKH) | `zpub` |
| `wpkh(ypub...)` | Wrapped SegWit (P2SH-P2WPKH) | `ypub` |
| `wpkh(tpub...)` | Testnet Native SegWit | `tpub` |
| `wpkh(upub...)` | Testnet Wrapped SegWit | `upub` |
| `wpkh(vpub...)` | Testnet Native SegWit | `vpub` |

Descriptors with key origin `[fingerprint/derivation/path]xpub.../branch/*` are fully supported. Checksum suffix `#xxxxxxxx` is stripped automatically.

---

## Detection taxonomy

Stealth runs **17 independent detectors** grouped into findings (actionable privacy violations) and warnings (informational).

### Severity scale

| Severity | Color | Meaning |
|---|---|---|
| `CRITICAL` | 🔴 Deep red | Immediate, severe privacy breach with full address linkage |
| `HIGH` | 🔴 Red | Significant vulnerability with high exploitation risk |
| `MEDIUM` | 🟡 Yellow | Moderate risk; exploitable with analyst effort |
| `LOW` | 🟢 Green | Minor fingerprint or informational finding |
| `INFO` | ⚪ Gray | Contextual information, no direct risk |

---

### `CIOH` — Common Input Ownership Heuristic
**Severity: CRITICAL / HIGH**

When multiple UTXOs from different addresses are co-spent in a single transaction, blockchain analysts assume all those addresses belong to the same wallet. This is the most powerful address clustering heuristic used in professional chain analysis.

- **CRITICAL** when 100% of inputs are yours (pure wallet consolidation)
- **HIGH** when some inputs are external (partial ownership)
- **Fix:** Use coin control to spend one UTXO at a time. If consolidation is necessary, do it via CoinJoin.

---

### `ADDRESS_REUSE` — Address Reuse
**Severity: HIGH**

Bitcoin addresses are designed to be used once. Reusing an address collapses all associated transactions into a single identifiable cluster, making it trivial to calculate total received, track spend patterns, and link counterparty identities.

- **Triggered by:** any wallet address that appears as a recipient in 2+ distinct transactions
- **Fix:** Use a wallet with proper HD key derivation. Never share the same address twice.

---

### `DUST` — Dust Attack Detection
**Severity: HIGH / MEDIUM / LOW**

Dust attacks send tiny amounts (≤ 1000 sats) to target addresses. The attack works when the victim later spends the dust together with real UTXOs, linking all those addresses via CIOH.

- **HIGH** (≤ 546 sats): unspent dust at cryptographic dust limit — immediate risk if spent
- **MEDIUM** (547–1000 sats): unspent dust above limit but still below safe threshold
- **LOW**: historical dust already spent — reveals a past attack attempt
- **Fix:** Freeze dust UTXOs in your wallet. Never spend them alongside normal UTXOs.

---

### `DUST_SPENDING` — Dust Co-Spending
**Severity: HIGH**

Detects transactions that actually spend dust inputs alongside normal inputs in the same transaction — the materialization of a dust attack. All co-spent addresses are now permanently linked on-chain.

- **Triggered by:** any transaction mixing dust inputs (≤ 1000 sats) with normal inputs (> 10 000 sats)
- **Fix:** If dust was already spent this way, the link is permanent. Going forward, use coin control to exclude dust UTXOs at all times.

---

### `CHANGE_DETECTION` — Identifiable Change Output
**Severity: MEDIUM**

Detects transactions where the change output is trivially distinguishable from the payment output using standard blockchain analysis heuristics: round payment vs. non-round change, script type mismatch between change and payment, or BIP-44 internal derivation path usage.

- **Triggered by:** one or more of: round payment / non-round change, change script type matches inputs but differs from payment, change on `/1/*` internal path
- **Fix:** Use PayJoin (BIP-78) so the change/payment distinction is broken. Select UTXOs that cover the exact payment amount (no change needed). Ensure change and payment use the same script type.

---

### `CONSOLIDATION` — UTXO Consolidation
**Severity: MEDIUM**

Detects UTXOs born from a prior consolidation transaction (>= 3 inputs, <= 2 outputs). Consolidations permanently link all input addresses under CIOH, and the consolidated UTXO carries that history forward.

- **Triggered by:** any current UTXO whose parent transaction has 3+ inputs and 1–2 outputs
- **Fix:** If fee savings require consolidation, do it through a CoinJoin so the link is indistinguishable from other participants.

---

### `SCRIPT_TYPE_MIXING` — Script Type Mixing
**Severity: HIGH**

Detects transactions that mix different input script types (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR) in the same transaction. Each type combination is rare and creates a strong fingerprint that narrows your anonymity set to a tiny subset of wallets capable of producing such a transaction.

- **Triggered by:** 2+ distinct input script types in a single transaction with multiple owned inputs
- **Fix:** Migrate all funds to a single address type (preferably Taproot / P2TR). Sweep legacy UTXOs through a CoinJoin before mixing with modern address types.

---

### `CLUSTER_MERGE` — Cross-Origin Cluster Merge
**Severity: HIGH**

Detects transactions that merge UTXOs originating from different funding chains (different grandparent transactions). This reveals that previously separate activity clusters belong to the same wallet, merging their histories permanently.

- **Triggered by:** a transaction whose inputs trace back to 2+ disjoint funding sources
- **Fix:** Use coin control to spend UTXOs from only one funding source per transaction. Keep UTXOs from different counterparties in separate wallets or accounts.

---

### `UTXO_AGE_SPREAD` — UTXO Age Spread
**Severity: LOW**

Detects wallets where unspent UTXOs have significantly different ages (measured in block height). A large age spread reveals long-term holding patterns, mixing of dormant and fresh coins, and can help analysts estimate wallet activity timelines.

- **Triggered by:** a spread of 10+ blocks between the oldest and newest UTXO
- **Fix:** Prefer FIFO coin selection (spend older UTXOs first). Route very old UTXOs through a CoinJoin to reset their history before spending alongside fresh funds.

---

### `EXCHANGE_ORIGIN` — Exchange Withdrawal Origin
**Severity: MEDIUM**

Detects UTXOs that likely originated from an exchange batch withdrawal, identified by high output count (5+), many unique recipients, and high input/median-output value ratio. Funds received this way carry a KYC fingerprint linking them to a centralized custodian.

- **Triggered by:** 2+ signals matched: output count ≥ 5, unique recipient count ≥ 5, input/median-output ratio > 10x
- **Fix:** Withdraw via Lightning Network instead of on-chain. If on-chain, pass the UTXO through a CoinJoin before using it for other payments.

---

### `TAINTED_UTXO_MERGE` — KYC-Tainted UTXO Merge
**Severity: HIGH**

A higher-severity specialization of CLUSTER_MERGE for the KYC case: detects transactions that merge a UTXO received directly from an exchange batch withdrawal with UTXOs from unrelated sources. This links your verified identity (from the exchange) to all other inputs in the transaction.

- **Triggered by:** a spending transaction that mixes one or more exchange-origin UTXOs with non-exchange UTXOs
- **Fix:** Never merge exchange-origin UTXOs with unrelated UTXOs. First pass the exchange UTXO through a CoinJoin to break the KYC link.

---

### `BEHAVIORAL_FINGERPRINT` — Behavioral Fingerprint
**Severity: MEDIUM**

Analyzes your entire sending history (3+ transactions required) for consistent behavioral patterns that make you identifiable: round payment amounts, uniform output counts, consistent fee rates, RBF signaling patterns, anti-fee-sniping locktime usage, and change/payment script type mismatch. Each pattern individually is minor; multiple patterns together create a strong cross-transaction fingerprint.

- **Triggered by:** 3+ send transactions with 1+ of the following patterns:
  - > 60% of payments are round numbers (multiples of 100,000 or 1,000,000 sats)
  - All send transactions have identical output count
  - Mixed input script types across transactions
  - RBF always enabled or always disabled (100% or 0%)
  - Locktime always non-zero (Bitcoin Core / Electrum) or always zero
  - Very consistent fee rate (coefficient of variation < 0.15)
  - Change uses different script type than payments
  - Always exactly N inputs per transaction
- **Fix:** Use wallet software with anti-fingerprinting defaults. Add small random satoshi offsets to payment amounts. Standardize on Taproot to reduce script-type distinctiveness.

---

### `DORMANT_UTXOS` — Dormant UTXOs *(warning)*
**Severity: LOW**

Detects UTXOs that are significantly older than the newest UTXO in the wallet (>= 100 block gap). Long-dormant coins create obvious age anomalies and suggest hoarding patterns that can help analysts identify wallet behavior over time.

- **Triggered by:** 1+ UTXOs with a block height >= 100 blocks older than the newest UTXO
- **Reported as:** warning (not finding) since dormancy is behavioral, not a direct vulnerability
- **Fix:** Route old UTXOs through a CoinJoin to reset their history, or spend with FIFO coin selection.

---

### `PAYJOIN_INTERACTION` — PayJoin / P2EP *(informational)*
**Severity: LOW**

Detects transactions with mixed inputs (both your addresses and external addresses) and outputs to your wallet — the hallmark of a PayJoin (BIP-78) or P2EP transaction. PayJoin breaks the CIOH assumption.

- **Triggered by:** transactions where both wallet-owned and external addresses appear as inputs, and at least one output returns to the wallet
- **Severity:** LOW — PayJoin is a **privacy improvement**; this is informational, not a vulnerability
- **Note:** If you did not intentionally use PayJoin, an external party contributed inputs alongside yours — review carefully.

---

### `WHIRLPOOL_COINJOIN` — Whirlpool CoinJoin *(informational)*
**Severity: LOW**

Detects transactions matching the Whirlpool CoinJoin structure: 4+ equal-value outputs at a known Whirlpool pool denomination (100,000 / 1,000,000 / 5,000,000 / 50,000,000 sats).

- **Triggered by:** transactions with 4+ equal outputs at a Whirlpool pool amount where at least one output is owned by the wallet
- **Severity:** LOW — Whirlpool is a **privacy improvement**; this is informational
- **Note:** Post-mix spending behavior determines whether the privacy gain is preserved. Avoid merging post-mix UTXOs with pre-mix coins.

---

### `FEE_FINGERPRINTING` — Round Fee Rate
**Severity: LOW**

Transactions using exact round fee rates (1, 2, 5, 10, 15, 20, 25, 50, 100 sat/vB) are a fingerprint of certain wallet software that uses fixed or rounded fee strategies.

- **Triggered by:** calculated fee rate (fee / vsize) matching any value in the round set
- **Fix:** Use wallets with dynamic fee calculation that produces non-round sat/vB values.

---

### `BATCH_PAYMENT_FINGERPRINT` — Batch Payment Pattern
**Severity: LOW**

Transactions with 5+ external outputs are characteristic of exchange or custodial batch withdrawals. If your wallet sent such a transaction, it reveals your role in the transaction graph.

- **Triggered by:** 5+ external (non-wallet) outputs in a transaction involving wallet inputs
- **Fix:** If you are not a payment processor, avoid sending to many recipients in a single transaction.

---

### `TINY_CHANGE_OUTPUT` — Tiny Change Output
**Severity: MEDIUM**

When the change output is less than 1% of the largest payment output and below 10,000 sats, it is trivially identifiable as change — breaking the ambiguity that normally protects change detection.

- **Triggered by:** change output < 1% of the largest external output AND < 10,000 sats
- **Fix:** Use wallets with change output optimization. Select UTXOs that minimize leftover change, or use PayJoin to eliminate the change output entirely.

---

## Quick start (hosted)

No installation required:

1. Open **[stealth.vercel.app](https://stealth-bitcoin.vercel.app)**
2. Paste your wallet descriptor into the input field
3. Select **Receive /0**, **Change /1**, or **Both** branches
4. Choose **Manual** (60 addresses) or **Auto gap-limit** scan mode
5. Click **Analyze Wallet**
6. Review the findings report; click any finding to expand details and TXID links
7. Download a PDF report with the **Export PDF** button

> ⚠️ **Privacy note:** On the hosted version your descriptor is sent to the Vercel API server for analysis. It is **never stored or logged**, but it does leave your device. For maximum privacy, [run locally](#running-locally) with an optional [Tor proxy](#tor--proxy).

---

## Running locally

Running locally means your descriptor and derived addresses **never leave your machine** — only individual Bitcoin addresses are queried against the public blockchain API.

### Prerequisites

| Dependency | Version | Purpose |
|---|---|---|
| Python | ≥ 3.10 | Analysis backend (`api/`) |
| Node.js | ≥ 18 | React frontend |
| pip | – | Python package manager |

### 1. Clone

```bash
git clone https://github.com/i2dor/stealth.git
cd stealth
```

### 2. Install backend dependencies

```bash
pip install -r requirements.txt

# Optional — required for Tor/SOCKS5 proxy support:
pip install requests[socks]
```

### 3. Start the backend

```bash
uvicorn api.scan:app --host 127.0.0.1 --port 8000
```

The API is available at `http://localhost:8000`.

### 4. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

### 5. Connect frontend to local backend

**Settings → API & Backend → Backend API base URL** → set to `http://localhost:8000`

Leave empty to use the hosted Vercel API.

---

## Tor / Proxy

Routing blockchain API requests through Tor hides your IP from Blockstream and Mempool. This is the **recommended privacy configuration** — your descriptor stays local, and address lookups are anonymized.

> ⚠️ The Tor proxy setting only works with the **local backend**. The hosted Vercel version cannot reach a local SOCKS5 socket.

### Setup

1. **Start Tor:** Tor Browser (listens on `127.0.0.1:9150`) or system daemon (`sudo systemctl start tor` → `127.0.0.1:9050`)
2. Start Stealth backend locally
3. **Settings → Tor / Proxy** → enter proxy URL:

| Setup | Proxy URL |
|---|---|
| Tor Browser | `socks5h://127.0.0.1:9150` |
| System Tor | `socks5h://127.0.0.1:9050` |
| Custom SOCKS5 | `socks5h://<host>:<port>` |

> Use `socks5h://` (not `socks5://`) so DNS resolution also goes through Tor.

4. Save settings and scan normally. Verify: after a scan, `scan_meta.proxy` in the API response should show your proxy URL.

---

## Privacy level comparison

| Setup | Descriptor leaves device? | IP exposed to Blockstream/Mempool? | Effort |
|---|---|---|---|
| Hosted (vercel.app) | ✅ To Vercel API | ✅ Yes | None |
| Local backend, no proxy | ❌ No | ✅ Yes | Low |
| **Local backend + Tor** | ❌ **No** | ❌ **No** | **Low** |
| Local backend + own Esplora node | ❌ No | ❌ No | High |

Recommended for most users: **Local backend + Tor**.

---

## Scan settings reference

| Setting | Default | Description |
|---|---|---|
| Backend API base URL | *(empty — Vercel)* | Override to point at a local backend |
| Blockstream API URL | `https://blockstream.info/api` | Primary blockchain API |
| Mempool API URL | `https://mempool.space/api` | Fallback blockchain API |
| Electrum host | *(empty)* | Optional self-hosted Electrum server |
| Electrum port | `50002` | SSL port (50001 for plain TCP) |
| SOCKS5 proxy URL | *(empty)* | `socks5h://127.0.0.1:9050` for Tor |
| Request delay (ms) | `300` | Delay between API requests (rate limiting protection) |
| Batch size | `60` | Addresses derived per scan batch |
| Gap limit | `20` | Consecutive empty addresses before stopping (BIP44) |

---

## Project structure

```
stealth/
├── api/
│   ├── scan.py             # Vercel serverless handler (GET /api/scan)
│   └── detect_public.py    # Core analysis engine + all detectors
├── frontend/
│   └── src/
│       ├── screens/
│       │   ├── InputScreen.jsx      # Descriptor input, scan options
│       │   ├── LoadingScreen.jsx    # Scan progress, ETA timer
│       │   ├── ReportScreen.jsx     # Findings report, export PDF
│       │   └── SettingsScreen.jsx   # API, proxy, scan configuration
│       ├── components/
│       │   ├── FindingCard.jsx      # Expandable finding with TXID links
│       │   └── VulnerabilityBadge.jsx  # Severity badge (CRITICAL/HIGH/MEDIUM/LOW/INFO)
│       └── services/
│           └── walletService.js     # API client (fetch + pagination)
├── requirements.txt
└── LICENSE                 # MIT
```

---

## API response format

```json
{
  "findings": [
    {
      "type": "CIOH",
      "severity": "HIGH",
      "description": "TX abc123... merges 3/3 of your inputs (100% ownership).",
      "details": {
        "txid": "abc123...",
        "our_inputs": 3,
        "total_inputs": 3,
        "our_input_addresses": ["bc1q..."]
      },
      "correction": "Use coin control to avoid merging multiple UTXOs..."
    }
  ],
  "warnings": [],
  "summary": {
    "findings": 1,
    "warnings": 0,
    "clean": false
  },
  "stats": {
    "transactions_analyzed": 56,
    "addresses_derived": 60,
    "utxos_found": 4,
    "active_addresses": 12
  },
  "scan_meta": {
    "mode": "manual",
    "branch_mode": "receive",
    "api_base": "https://blockstream.info/api",
    "request_delay_ms": 250,
    "proxy": null
  },
  "scan_window": {
    "offset": 0,
    "count": 60,
    "from_index": 0,
    "to_index": 59,
    "branch": 0
  }
}
```

---

## Privacy notice

Stealth does **not** store, log, or transmit your wallet descriptor beyond the ephemeral API call used to run the analysis. All analysis is **read-only** — no transactions are broadcast, no wallet state is modified, and the descriptor is not written to any disk, database, or log.

Querying Blockstream or Mempool.space reveals those Bitcoin addresses to those services, along with your IP address — unless you use the [Tor setup](#tor--proxy).

---

## License

MIT License. See [LICENSE](./LICENSE).

Forked from [stealth-bitcoin/stealth](https://github.com/stealth-bitcoin/stealth). Original copyright © 2026 Stealth Contributors. Modifications © 2026 i2dor.
