# Stealth

A privacy audit tool for Bitcoin wallets. Stealth analyzes the transaction history of a wallet descriptor and surfaces privacy findings from real on-chain heuristics.

## What it does

Paste a Bitcoin wallet descriptor into the input screen and click **Analyze**. Stealth derives addresses from the descriptor, scans wallet-related chain history via the Blockstream/Mempool public APIs, and returns a structured report with `findings` and `warnings`.

## Quick start (hosted)

The easiest way to use Stealth is the hosted version at **[stealth.vercel.app](https://vercel.com/arthurs-projects-bf400950/stealth)**.

> ⚠️ **Privacy note:** On the hosted version your descriptor is sent to the Vercel API server for analysis. It is never stored or logged, but it does leave your device. For maximum privacy, [run locally](#running-locally).

## Running locally

Running the backend on your own machine means your descriptor and derived addresses **never leave your device** (only the individual Bitcoin addresses are queried against Blockstream/Mempool).

### Prerequisites

| Dependency | Version | Purpose |
|---|---|---|
| Python | ≥ 3.10 | Analysis backend (`api/`) |
| Node.js | ≥ 18 | React frontend |
| pip | – | Python dependencies |

### 1. Clone

```bash
git clone https://github.com/i2dor/stealth.git
cd stealth
```

### 2. Install backend dependencies

```bash
pip install -r requirements.txt
# SOCKS5/Tor support (optional but recommended):
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

### 5. Point the frontend at your local backend

In the app go to **Settings → API & Backend** and set:

```
Backend API base URL: http://localhost:8000
```

Leave empty to use the hosted Vercel API.

---

## Tor / Proxy

Routing blockchain API requests through Tor hides your IP address from Blockstream and Mempool. This is the recommended privacy setup for most users: your descriptor stays local, and the address lookups are anonymized.

### Requirements

- Tor daemon running locally (via **Tor Browser** or the `tor` system package)
- Backend running locally (Tor proxy is **not** available on the hosted Vercel version, since serverless functions cannot reach a local SOCKS5 socket)
- `PySocks` installed: `pip install requests[socks]`

### Setup

1. Start Tor:
   - **Tor Browser:** launch it and keep it open (listens on `127.0.0.1:9150` by default)
   - **System Tor daemon:** `sudo systemctl start tor` (listens on `127.0.0.1:9050`)

2. Start Stealth backend locally (see [Running locally](#running-locally)).

3. In the Stealth UI go to **Settings → Tor / Proxy** and enter:

   | Setup | Proxy URL |
   |---|---|
   | Tor Browser | `socks5h://127.0.0.1:9150` |
   | System Tor daemon | `socks5h://127.0.0.1:9050` |
   | Custom SOCKS5 | `socks5h://<host>:<port>` |

   > Use `socks5h://` (not `socks5://`) so that DNS resolution also goes through Tor, preventing hostname leaks.

4. Click **Save settings** and run a scan normally.

### Verify Tor is working

After a scan, open the browser console and check the `scan_meta.proxy` field in the API response — it should show your proxy URL:

```json
"scan_meta": {
  "proxy": "socks5h://127.0.0.1:9050",
  ...
}
```

If `proxy` is `null`, the proxy was not applied (check that the backend URL in Settings points to your local instance, not Vercel).

---

## Privacy levels

| Setup | Descriptor exposed? | IP exposed to Blockstream/Mempool? | Effort |
|---|---|---|---|
| Hosted (vercel.app) | To Vercel API | Yes | None |
| Local backend, no proxy | No | Yes | Low |
| **Local backend + Tor** | **No** | **No** | **Low** |
| Local backend + own Esplora node | No | No | High |

The recommended setup for most users is **Local backend + Tor**.

---

## Detection taxonomy

| Type | Severity | Meaning |
|---|---|---|
| `CIOH` | HIGH | Common Input Ownership Heuristic — multiple of your UTXOs co-spent in one tx, linking them. |
| `ADDRESS_REUSE` | HIGH | An address of yours received funds in multiple transactions, linking history. |
| `DUST` | MEDIUM/HIGH | Dust UTXO present — if spent with normal inputs, it links your UTXOs together. |
| `PAYJOIN_INTERACTION` | LOW | Transaction has mixed inputs (yours + external) consistent with PayJoin/P2EP. |
| `WHIRLPOOL_COINJOIN` | LOW | Transaction matches Whirlpool CoinJoin pattern. Good for privacy; ensure post-mix spend is careful. |
| `FEE_FINGERPRINTING` | LOW | Round fee rate (e.g. 1, 5, 10 sat/vB) fingerprints your wallet software. |
| `BATCH_PAYMENT_FINGERPRINT` | LOW | 5+ external outputs in one tx — typical of exchange/custodial batching. |
| `TINY_CHANGE_OUTPUT` | MEDIUM | Change output is disproportionately small relative to payment, trivially identifiable. |

`severity` values: `LOW`, `MEDIUM`, `HIGH`.

---

## Settings reference

| Setting | Default | Description |
|---|---|---|
| Backend API base URL | *(empty — uses Vercel)* | Override to point at your local backend |
| Blockstream API URL | `https://blockstream.info/api` | Primary API for address/tx lookups |
| Mempool API URL | `https://mempool.space/api` | Fallback API |
| Electrum host | *(empty)* | Your own Electrum server host |
| Electrum port | `50002` | SSL port (50001 for plain TCP) |
| SOCKS5 proxy URL | *(empty)* | `socks5h://127.0.0.1:9050` for Tor |
| Request delay (ms) | `300` | Delay between API requests to avoid rate-limiting |
| Batch size | `60` | Addresses derived per scan batch |
| Gap limit | `20` | Consecutive empty addresses before stopping (BIP44 standard) |

---

## Project structure

```
stealth/
├── api/
│   ├── scan.py           # Vercel serverless handler (GET /api/scan)
│   └── detect_public.py  # Core analysis engine + detectors
├── frontend/
│   └── src/
│       ├── screens/      # InputScreen, LoadingScreen, ReportScreen, SettingsScreen
│       └── services/     # walletService.js (API client)
└── requirements.txt
```

---

## Privacy notice

Stealth does **not** store, log, or transmit your wallet descriptor beyond the ephemeral API call used to run the analysis. All analysis is read-only. The descriptor is not written to disk, databases, or logs on the Vercel infrastructure.

However, querying any third-party API (Blockstream, Mempool) for your Bitcoin addresses does reveal those addresses to that service, along with your IP address — unless you use the [Tor setup](#tor--proxy) above.
