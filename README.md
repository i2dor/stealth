# Stealth — Bitcoin Wallet Privacy Analyzer

> Analyze the on-chain privacy of any Bitcoin wallet descriptor. Stealth derives addresses from your descriptor, scans transaction history via public blockchain APIs, and returns a structured report of privacy vulnerabilities — with severity ratings, explanations, and actionable remediation steps.

**Live demo:** [stealth.vercel.app](https://stealth-bitcoin.vercel.app)

---

## What it does

Bitcoin transactions are pseudonymous, not anonymous. Every transaction you make leaves fingerprints that can be used to cluster addresses, infer wallet software, link identities, and trace fund flows. Stealth automates the privacy audit process:

1. **You paste a wallet descriptor** (e.g. `wpkh([a1b2c3d4/84h/0h/0h]xpub.../0/*)`) into the UI
2. **Stealth derives Bitcoin addresses** from the descriptor using BIP32 key derivation
3. **It fetches transaction history** for each address from Blockstream or Mempool.space
4. **Eight heuristic detectors** analyze the transaction graph for privacy leaks
5. **A full report** is returned — findings with severity, descriptions, affected transactions, and how to fix each issue
6. **Export to PDF** — download a formatted report for offline review

All analysis is **read-only**. Stealth never broadcasts transactions or modifies any wallet state.

---

## Supported descriptor formats

| Format | Script type | Example prefix |
|---|---|---|
| `wpkh(xpub...)` | Native SegWit (P2WPKH) | `xpub` |
| `wpkh(zpub...)` | Native SegWit (P2WPKH) | `zpub` |
| `wpkh(ypub...)` | Wrapped SegWit (P2SH-P2WPKH) | `ypub` |
| `wpkh(tpub...)` | Testnet Native SegWit | `tpub` |
| `wpkh(upub...)` | Testnet Wrapped SegWit | `upub` |
| `wpkh(vpub...)` | Testnet Native SegWit | `vpub` |

Descriptors with key origin `[fingerprint/derivation/path]xpub.../branch/*` are supported. Checksum suffix `#xxxxxxxx` is stripped automatically.

---

## Privacy detectors

Stealth runs eight independent heuristic detectors on every scan:

### `CIOH` — Common Input Ownership Heuristic · **HIGH**
When multiple UTXOs from different addresses are co-spent in a single transaction input set, blockchain analysts assume all those addresses belong to the same wallet. This is the most powerful clustering heuristic used in chain analysis.

- **Triggered by:** any transaction where two or more of your wallet's addresses appear as inputs simultaneously
- **Why it matters:** permanently links your addresses together in the public ledger
- **How to fix:** use CoinJoin, avoid merging UTXOs, or use coin control to spend one UTXO at a time

---

### `ADDRESS_REUSE` — Address Reuse · **HIGH**
Bitcoin addresses are designed to be used once. Reusing an address collapses all transactions into a single identifiable cluster, making it trivial to calculate total received, track spend patterns, and link identities across payments.

- **Triggered by:** any wallet address that appears as a recipient in more than one distinct transaction
- **Why it matters:** eliminates the pseudonymity of the UTXO model
- **How to fix:** use a wallet with proper HD key derivation and never share the same address twice

---

### `DUST` — Dust Attack · **MEDIUM / HIGH**
Dust attacks send tiny amounts of BTC (below 1000 satoshis) to target addresses. The dust itself is worthless — the attack works when the victim later spends the dust together with real UTXOs, linking all those addresses in a CIOH cluster.

- **Triggered by:** any UTXO in the wallet at or below 1000 satoshis
- **Why it matters:** unspent dust is a ticking time bomb — spending it reveals your wallet cluster
- **How to fix:** never spend dust UTXOs; mark them as "do not spend" in your wallet software

---

### `TINY_CHANGE_OUTPUT` — Tiny Change Output · **MEDIUM**
When a transaction creates a change output that is disproportionately small relative to the payment amount, the change output is trivially identifiable. Analysts use this to distinguish payments from change, reconstructing wallet balances and payment direction.

- **Triggered by:** change outputs that are less than ~5% of the largest output in the transaction
- **Why it matters:** breaks change detection ambiguity, exposing wallet balance and payment size
- **How to fix:** use wallets that implement change output blinding (e.g. PayJoin, or wallets with amount randomization)

---

### `FEE_FINGERPRINTING` — Fee Rate Fingerprinting · **LOW**
Different wallet software uses different fee calculation strategies. Round fee rates (1, 5, 10 sat/vB) are a strong fingerprint for certain wallets, and unusual fee structures narrow down the wallet software version used to create a transaction.

- **Triggered by:** transactions using exact round fee rates (1, 2, 5, 10, 20, 50, 100 sat/vB)
- **Why it matters:** links multiple transactions to the same wallet software, enabling clustering
- **How to fix:** use wallets with randomized fee selection; avoid manually setting round fee values

---

### `BATCH_PAYMENT_FINGERPRINT` — Batch Payment Fingerprint · **LOW**
Transactions with 5 or more external outputs are characteristic of custodial exchange withdrawals or payment processors batching payouts. Receiving from such transactions may indicate a connection to a centralized service.

- **Triggered by:** any transaction in wallet history with ≥ 5 distinct external output addresses
- **Why it matters:** may indicate KYC-linked exchange activity in wallet history
- **How to fix:** use peer-to-peer services for receiving; be aware of the traceability of custodial sources

---

### `WHIRLPOOL_COINJOIN` — Whirlpool CoinJoin Detection · **LOW** (informational)
Whirlpool is Samourai Wallet's CoinJoin implementation. Transactions with equal-value outputs matching Whirlpool pool denominations (0.001, 0.01, 0.05, or 0.5 BTC) and the correct structure are flagged as CoinJoin participation.

- **Triggered by:** transactions matching Whirlpool pool amounts and input/output count patterns
- **Severity:** LOW — CoinJoin is a **privacy improvement**; this is informational, not a vulnerability
- **Why it matters:** post-mix spending behavior determines whether the privacy gain is preserved
- **How to fix:** ensure post-mix UTXOs are spent carefully; avoid merging them with pre-mix coins

---

### `PAYJOIN_INTERACTION` — PayJoin / P2EP Interaction · **LOW** (informational)
PayJoin transactions involve inputs from both the sender and receiver, breaking the CIOH assumption. This is detected when a transaction contains inputs from both wallet addresses and external addresses.

- **Triggered by:** transactions where both your addresses and external addresses appear as inputs
- **Severity:** LOW — PayJoin is a **privacy improvement**; this is informational
- **Why it matters:** indicates sophisticated privacy-conscious transaction behavior

---

## Severity scale

| Severity | Color | Meaning |
|---|---|---|
| `CRITICAL` | 🔴 Deep red | Immediate, severe privacy breach |
| `HIGH` | 🔴 Red | Significant privacy vulnerability, high exploitation risk |
| `MEDIUM` | 🟡 Yellow | Moderate risk; exploitable with some analyst effort |
| `LOW` | 🟢 Green | Minor fingerprint or informational finding |
| `INFO` | ⚪ Gray | Contextual information, no direct risk |

---

## Quick start (hosted)

No installation required. The easiest way to use Stealth:

1. Open **[stealth.vercel.app](https://stealth-bitcoin.vercel.app)**
2. Paste your wallet descriptor into the input field
3. Select **Receive /0**, **Change /1**, or **Both** branches
4. Choose **Manual** (60 addresses) or **Auto gap-limit** scan mode
5. Click **Analyze Wallet**
6. Review the findings report; click any finding to expand details
7. Download a PDF report with the **Export PDF** button

> ⚠️ **Privacy note:** On the hosted version your descriptor is sent to the Vercel API server for analysis. It is **never stored or logged**, but it does leave your device. For maximum privacy, [run locally](#running-locally) with an optional [Tor proxy](#tor--proxy).

---

## Running locally

Running locally means your descriptor and derived addresses **never leave your machine** — only individual Bitcoin addresses are queried against the public API.

### Prerequisites

| Dependency | Version | Purpose |
|---|---|---|
| Python | ≥ 3.10 | Analysis backend (`api/`) |
| Node.js | ≥ 18 | React frontend |
| pip | – | Python package manager |

### 1. Clone the repository

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

The API will be available at `http://localhost:8000`.

### 4. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

### 5. Connect the frontend to your local backend

In the app: **Settings → API & Backend → Backend API base URL** → set to:

```
http://localhost:8000
```

Leave empty to use the hosted Vercel API.

---

## Tor / Proxy

Routing blockchain API requests through Tor hides your IP address from Blockstream and Mempool. This is the **recommended privacy configuration** — your descriptor stays local, and address lookups are anonymized.

> ⚠️ The Tor proxy setting is only available when running the **local backend**. The hosted Vercel version cannot reach a local SOCKS5 socket.

### Requirements

- Tor daemon running locally (Tor Browser or system `tor` package)
- Local backend running (`uvicorn api.scan:app ...`)
- PySocks: `pip install requests[socks]`

### Setup

1. **Start Tor:**
   - Tor Browser: launch and keep open (default: `127.0.0.1:9150`)
   - System daemon: `sudo systemctl start tor` (default: `127.0.0.1:9050`)

2. In Stealth UI: **Settings → Tor / Proxy** → enter proxy URL:

   | Setup | Proxy URL |
   |---|---|
   | Tor Browser | `socks5h://127.0.0.1:9150` |
   | System Tor | `socks5h://127.0.0.1:9050` |
   | Custom SOCKS5 | `socks5h://<host>:<port>` |

   > Use `socks5h://` (not `socks5://`) so that DNS resolution also goes through Tor, preventing hostname leaks.

3. Save settings and run a scan normally.

### Verify it's working

After a scan, check the `scan_meta.proxy` field in the API response — it should show your proxy URL:

```json
"scan_meta": {
  "proxy": "socks5h://127.0.0.1:9050"
}
```

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
| Gap limit | `20` | Consecutive empty addresses before stopping (BIP44 standard) |

---

## Project structure

```
stealth/
├── api/
│   ├── scan.py             # Vercel serverless handler (GET /api/scan)
│   └── detect_public.py    # Core analysis engine + all eight detectors
├── frontend/
│   └── src/
│       ├── screens/
│       │   ├── InputScreen.jsx      # Descriptor input, scan options
│       │   ├── LoadingScreen.jsx    # Scan progress, ETA timer
│       │   ├── ReportScreen.jsx     # Findings report, export PDF
│       │   └── SettingsScreen.jsx   # API, proxy, scan configuration
│       ├── components/
│       │   ├── FindingCard.jsx      # Expandable finding with details + TXID links
│       │   └── VulnerabilityBadge.jsx  # Severity badge (CRITICAL/HIGH/MEDIUM/LOW/INFO)
│       └── services/
│           └── walletService.js     # API client (fetch + pagination)
├── requirements.txt
└── LICENSE                 # MIT
```

---

## API response format

The `/api/scan` endpoint returns a JSON object with the following top-level structure:

```json
{
  "findings": [
    {
      "type": "CIOH",
      "severity": "HIGH",
      "description": "Co-spent inputs link 3 of your addresses in tx abc123...",
      "details": {
        "txid": "abc123...",
        "our_addresses": [...]
      },
      "correction": "Avoid merging UTXOs from different addresses in a single transaction..."
    }
  ],
  "warnings": [],
  "summary": {
    "addresses_scanned": 60,
    "transactions_analyzed": 56,
    "findings_count": 1,
    "active_addresses": 12
  },
  "scan_meta": {
    "descriptor": "wpkh([...]xpub.../0/*)",
    "offset": 0,
    "count": 60,
    "proxy": null,
    "api_base": "https://blockstream.info/api"
  }
}
```

---

## Privacy notice

Stealth does **not** store, log, or transmit your wallet descriptor beyond the ephemeral API call used to run the analysis. All analysis is **read-only** — no transactions are broadcast, no wallet state is modified, and the descriptor is not written to any disk, database, or log on Vercel infrastructure.

Querying Blockstream or Mempool.space for your Bitcoin addresses does reveal those addresses to those services, along with your IP address — unless you use the [Tor setup](#tor--proxy) described above.

---

## License

MIT License. See [LICENSE](./LICENSE).

Forked from [stealth-bitcoin/stealth](https://github.com/stealth-bitcoin/stealth). Original copyright (c) 2026 Stealth Contributors. Modifications copyright (c) 2026 i2dor.
