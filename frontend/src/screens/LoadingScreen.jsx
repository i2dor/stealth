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
  "\ud83d\udca1 Always generate a fresh address for every payment \u2014 reusing addresses links your transactions together.",
  "\ud83d\udd12 Use coin control to avoid merging UTXOs from different sources in a single transaction.",
  "\u26a1 Lightning Network payments don't appear on-chain \u2014 ideal for frequent, small transactions.",
  "\ud83c\udf00 CoinJoin (Whirlpool, JoinMarket) breaks the link between your inputs and outputs.",
  "\ud83d\udeab Avoid round amounts when sending \u2014 e.g. 0.1 BTC signals exactly which output is the payment.",
  "\ud83d\udced Never share your xpub/zpub \u2014 it exposes your entire transaction history and future addresses.",
  "\ud83d\udd17 CIOH (Common Input Ownership Heuristic): merging inputs hints that they belong to the same wallet.",
  "\ud83d\udd75\ufe0f Blockchain analysis firms use cluster analysis \u2014 every UTXO merge is a clue about your identity.",
  "\ud83c\udff7\ufe0f Dust attacks: tiny UTXOs sent to your address are used to trace you when you spend them.",
  "\ud83d\udcb8 Paying high fees on a low-fee transaction reveals your wallet software and version.",
  "\ud83d\udd04 PayJoin (P2EP) makes transactions look like normal payments, breaking the CIOH assumption.",
  "\ud83d\udccf Taproot outputs (bc1p\u2026) are indistinguishable from each other \u2014 better privacy by default.",
  "\ud83c\udf10 Use your own full node + Electrum to avoid leaking addresses to third-party servers.",
  "\u23f3 Time-stamping heuristics: spending outputs too quickly reveals spending patterns \u2014 wait before consolidating.",
  "\ud83d\udd22 Avoid address reuse in change outputs \u2014 wallets that recycle change addresses are trivially tracked.",
  "\ud83e\uddc5 Tor + Bitcoin Core: run your node over Tor to prevent IP-level transaction tracing.",
  "\ud83d\udcca Fee fingerprinting: some wallets use unique fee calculation patterns that reveal which software you use.",
  "\ud83d\udd11 BIP47 reusable payment codes let you receive payments without reusing addresses publicly.",
  "\ud83d\udcd0 Equal-output CoinJoins are the strongest on-chain privacy tool \u2014 outputs of the same size are indistinguishable.",
  "\ud83d\udee1\ufe0f The safest UTXO strategy: spend UTXOs from the same source together, never mix sources.",
  "\ud83e\uddf1 UTXO consolidation is a privacy risk \u2014 merging many small UTXOs reveals they all belong to you.",
  "\ud83d\udd0d Blockchain explorers log your IP when you look up your own transactions \u2014 use Tor or a VPN.",
  "\ud83d\udce6 Large UTXO sets slow down your wallet and increase your on-chain footprint \u2014 consolidate privately via CoinJoin.",
  "\ud83c\udfaf Avoid spending change immediately after receiving it \u2014 the timing creates a strong link between sender and receiver.",
  "\ud83d\uddc2\ufe0f Labelling your UTXOs in your wallet (e.g. 'KYC exchange', 'P2P buy') prevents accidental mixing.",
  "\ud83d\udd10 Hardware wallets sign transactions offline \u2014 but they can still leak your xpub to a compromised host.",
  "\ud83d\udce1 SPV wallets (like Electrum without your own server) leak all your addresses to the server operator.",
  "\ud83c\udfe6 KYC exchange outputs are tainted \u2014 spending them alongside non-KYC UTXOs links your identity to both.",
  "\ud83d\udd00 Payjoin breaks the assumption that all inputs in a transaction belong to the same person.",
  "\ud83c\udfb2 Randomise your transaction output ordering \u2014 some wallets always put change last, making it easy to identify.",
  "\ud83d\udd70\ufe0f Avoid broadcasting transactions at predictable times \u2014 patterns in timing can correlate to your timezone.",
  "\ud83d\udcc9 Avoid creating tiny change outputs (below dust threshold) \u2014 they can't be spent and reveal your wallet type.",
  "\ud83e\uddee Check your wallet's change address gap limit \u2014 if too small, it may miss UTXOs on a restore.",
  "\ud83d\udd0f Silent payments (BIP352) let you receive funds at a static address without any on-chain address reuse.",
  "\ud83c\udf0d Multi-path payments on Lightning split your payment across channels, reducing traceability even further.",
  "\ud83e\udde9 Coinjoin entropy (measured in bits) tells you how hard it is to de-mix outputs \u2014 aim for >50 bits.",
  "\ud83d\udea7 Avoid using the same wallet for both savings (cold) and spending (hot) \u2014 keep UTXOs strictly separated.",
  "\u26a0\ufe0f Watch-only wallets connected to a public Electrum server expose every address you monitor.",
  "\ud83d\udddd\ufe0f Multisig setups reveal their policy on-chain unless you use MuSig2 (Taproot key-path spend).",
  "\ud83d\udcf2 Mobile wallets that use a centralised API (e.g. Blockchain.com) send your addresses to their servers.",
]

function shuffle(arr) {
  const a = [...arr]
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]]
  }
  return a
}

export default function LoadingScreen({ descriptor, autoMode = false }) {
  const MESSAGES = autoMode ? MESSAGES_AUTO : MESSAGES_MANUAL
  const [msgIndex, setMsgIndex] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const [tipIndex, setTipIndex] = useState(0)
  const [tipFade, setTipFade] = useState(true)
  const shuffledTips = useRef(shuffle(PRIVACY_TIPS))

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
          {slowNote && (
            <span className={styles.timerNote}>{slowNote}</span>
          )}
        </div>
      </div>

      <div className={styles.progressBar}>
        <div className={styles.progressFill} />
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
