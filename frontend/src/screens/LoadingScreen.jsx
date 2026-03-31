import { useState, useEffect, useRef } from 'react'
import styles from './LoadingScreen.module.css'

const MESSAGES_MANUAL = [
  'Resolving descriptors',
  'Deriving addresses',
  'Importing & scanning blockchain',
  'Loading transaction history',
  'Running vulnerability detectors',
]

const MESSAGES_AUTO = [
  'Resolving descriptors',
  'Deriving addresses',
  'Scanning batch...',
  'Checking gap limit',
  'Loading transactions',
  'Running vulnerability detectors',
  'Scanning next batch...',
  'Checking for address reuse',
  'Checking for CIOH patterns',
  'Checking gap limit',
]

const PRIVACY_TIPS = [
  "💡 Always generate a fresh address for every payment — reusing addresses links your transactions together.",
  "🔒 Use coin control to avoid merging UTXOs from different sources in a single transaction.",
  "⚡ Lightning Network payments don't appear on-chain — ideal for frequent, small transactions.",
  "🌀 CoinJoin (Whirlpool, JoinMarket) breaks the link between your inputs and outputs.",
  "🚫 Avoid round amounts when sending — e.g. 0.1 BTC signals exactly which output is the payment.",
  "📭 Never share your xpub/zpub — it exposes your entire transaction history and future addresses.",
  "🔗 CIOH (Common Input Ownership Heuristic): merging inputs hints that they belong to the same wallet.",
  "🕵️ Blockchain analysis firms use cluster analysis — every UTXO merge is a clue about your identity.",
  "🏷️ Dust attacks: tiny UTXOs sent to your address are used to trace you when you spend them.",
  "💸 Paying high fees on a low-fee transaction reveals your wallet software and version.",
  "🔄 PayJoin (P2EP) makes transactions look like normal payments, breaking the CIOH assumption.",
  "📏 Taproot outputs (bc1p…) are indistinguishable from each other — better privacy by default.",
  "🌐 Use your own full node + Electrum to avoid leaking addresses to third-party servers.",
  "⏳ Time-stamping heuristics: spending outputs too quickly reveals spending patterns — wait before consolidating.",
  "🔢 Avoid address reuse in change outputs — wallets that recycle change addresses are trivially tracked.",
  "🧅 Tor + Bitcoin Core: run your node over Tor to prevent IP-level transaction tracing.",
  "📊 Fee fingerprinting: some wallets use unique fee calculation patterns that reveal which software you use.",
  "🔑 BIP47 reusable payment codes let you receive payments without reusing addresses publicly.",
  "📐 Equal-output CoinJoins are the strongest on-chain privacy tool — outputs of the same size are indistinguishable.",
  "🛡️ The safest UTXO strategy: spend UTXOs from the same source together, never mix sources.",
  "🧱 UTXO consolidation is a privacy risk — merging many small UTXOs reveals they all belong to you.",
  "🔍 Blockchain explorers log your IP when you look up your own transactions — use Tor or a VPN.",
  "📦 Large UTXO sets slow down your wallet and increase your on-chain footprint — consolidate privately via CoinJoin.",
  "🎯 Avoid spending change immediately after receiving it — the timing creates a strong link between sender and receiver.",
  "🗂️ Labelling your UTXOs in your wallet (e.g. 'KYC exchange', 'P2P buy') prevents accidental mixing.",
  "🔐 Hardware wallets sign transactions offline — but they can still leak your xpub to a compromised host.",
  "📡 SPV wallets (like Electrum without your own server) leak all your addresses to the server operator.",
  "🏦 KYC exchange outputs are tainted — spending them alongside non-KYC UTXOs links your identity to both.",
  "🔀 Payjoin breaks the assumption that all inputs in a transaction belong to the same person.",
  "🎲 Randomise your transaction output ordering — some wallets always put change last, making it easy to identify.",
  "🕰️ Avoid broadcasting transactions at predictable times — patterns in timing can correlate to your timezone.",
  "📉 Avoid creating tiny change outputs (below dust threshold) — they can't be spent and reveal your wallet type.",
  "🧮 Check your wallet's change address gap limit — if too small, it may miss UTXOs on a restore.",
  "🔏 Silent payments (BIP352) let you receive funds at a static address without any on-chain address reuse.",
  "🌍 Multi-path payments on Lightning split your payment across channels, reducing traceability even further.",
  "🧩 Coinjoin entropy (measured in bits) tells you how hard it is to de-mix outputs — aim for >50 bits.",
  "🚧 Avoid using the same wallet for both savings (cold) and spending (hot) — keep UTXOs strictly separated.",
  "⚠️ Watch-only wallets connected to a public Electrum server expose every address you monitor.",
  "🗝️ Multisig setups reveal their policy on-chain unless you use MuSig2 (Taproot key-path spend).",
  "📲 Mobile wallets that use a centralised API (e.g. Blockchain.com) send your addresses to their servers.",
]

function shuffle(arr) {
  const a = [...arr]
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]]
  }
  return a
}

// Typical durations in seconds for estimating ETA
// Manual scan ~60 addresses: ~15-40s depending on wallet activity
// Auto scan: ~20-120s depending on gap limit hits
const MANUAL_TYPICAL_DURATION = 25 // seconds, median for a quiet wallet
const AUTO_TYPICAL_DURATION = 60  // seconds, median for auto scan

export default function LoadingScreen({ descriptor, autoMode = false, addressCount = 60 }) {
  const MESSAGES = autoMode ? MESSAGES_AUTO : MESSAGES_MANUAL
  const [msgIndex, setMsgIndex] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const [tipIndex, setTipIndex] = useState(0)
  const [tipFade, setTipFade] = useState(true)
  const shuffledTips = useRef(shuffle(PRIVACY_TIPS))

  // ETA estimation: use a weighted blend of
  // (a) typical duration for this scan type
  // (b) if elapsed > 50% of typical, extrapolate linearly
  const typicalDuration = autoMode ? AUTO_TYPICAL_DURATION : MANUAL_TYPICAL_DURATION

  // Progress 0→1 capped at 0.95 so bar never "completes"
  const progressFraction = Math.min(0.95, elapsed / typicalDuration)

  // ETA: only show after 4s, hide once elapsed > typical (we're past the estimate)
  let etaText = null
  if (elapsed >= 4 && elapsed < typicalDuration * 1.5) {
    const remaining = Math.max(1, Math.round(typicalDuration - elapsed))
    if (remaining > 3) {
      etaText = `ETA ~${remaining}s`
    }
  }

  useEffect(() => {
    setMsgIndex(0)
    const msgInterval = setInterval(() => {
      setMsgIndex((i) => (i + 1) % MESSAGES.length)
    }, autoMode ? 2200 : 1000)
    return () => clearInterval(msgInterval)
  }, [autoMode])

  useEffect(() => {
    const timerInterval = setInterval(() => {
      setElapsed((s) => s + 1)
    }, 1000)
    return () => clearInterval(timerInterval)
  }, [])

  useEffect(() => {
    if (elapsed === 1) {
      setTipIndex(0)
      setTipFade(true)
    }
    if (elapsed > 1 && (elapsed - 1) % 5 === 0) {
      setTipFade(false)
      setTimeout(() => {
        setTipIndex((i) => (i + 1) % shuffledTips.current.length)
        setTipFade(true)
      }, 400)
    }
  }, [elapsed])

  const shortDescriptor = descriptor.length > 48
    ? `${descriptor.slice(0, 48)}\u2026`
    : descriptor

  const formatTime = (s) => {
    const m = Math.floor(s / 60)
    const sec = s % 60
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`
  }

  const slowNote = autoMode
    ? elapsed >= 15 ? ' \u2014 auto-scanning, checking gap limit...'
      : elapsed >= 5 ? ' \u2014 scanning batches'
      : ''
    : elapsed >= 10 ? ' \u2014 large wallet, please wait' : ''

  return (
    <div className={styles.root}>
      <div className={styles.scanner}>
        <div className={styles.ring} />
        <div className={styles.ring2} />
        <div className={styles.ring3} />
        <div className={styles.logoMark}>
          ST<span>LT</span>H
        </div>
      </div>

      <div className={styles.status}>
        {autoMode && (
          <div className={styles.autoModeBadge}>\u26a1 Auto gap-limit scan</div>
        )}
        <div key={msgIndex} className={styles.statusText}>
          {MESSAGES[msgIndex]}<span className={styles.dots}>...</span>
        </div>
        <div className={styles.descriptor}>{shortDescriptor}</div>
        <div className={styles.timer}>
          <span className={styles.timerIcon}>\u23f1</span>
          {formatTime(elapsed)}
          {etaText && (
            <span className={styles.timerEta}>{etaText}</span>
          )}
          {!etaText && slowNote && (
            <span className={styles.timerNote}>{slowNote}</span>
          )}
        </div>
      </div>

      <div className={styles.progressBar}>
        <div
          className={styles.progressFill}
          style={{ width: `${progressFraction * 100}%` }}
        />
      </div>

      {elapsed >= 1 && (
        <div
          className={styles.tipBox}
          style={{ opacity: tipFade ? 1 : 0, transition: 'opacity 0.4s ease' }}
        >
          <div className={styles.tipLabel}>Privacy tip</div>
          <div className={styles.tipText}>{shuffledTips.current[tipIndex]}</div>
        </div>
      )}
    </div>
  )
}
