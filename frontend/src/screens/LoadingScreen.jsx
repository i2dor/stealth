import { useState, useEffect } from 'react'
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
  '💡 Always generate a fresh address for every payment — reusing addresses links your transactions together.',
  '🔒 Use coin control to avoid merging UTXOs from different sources in a single transaction.',
  '⚡ Lightning Network payments don't appear on-chain — ideal for frequent, small transactions.',
  '🌀 CoinJoin (Whirlpool, JoinMarket) breaks the link between your inputs and outputs.',
  '🚫 Avoid round amounts when sending — e.g. 0.1 BTC signals exactly which output is the payment.',
  '📭 Never share your xpub/zpub — it exposes your entire transaction history and future addresses.',
  '🔗 CIOH (Common Input Ownership Heuristic): merging inputs hints that they belong to the same wallet.',
  '🕵️ Blockchain analysis firms use cluster analysis — every UTXO merge is a clue about your identity.',
  '🏷️ Dust attacks: tiny UTXOs sent to your address are used to trace you when you spend them.',
  '💸 Paying high fees on a low-fee transaction reveals your wallet software and version.',
  '🔄 PayJoin (P2EP) makes transactions look like normal payments, breaking the CIOH assumption.',
  '📏 Taproot outputs (bc1p…) are indistinguishable from each other — better privacy by default.',
  '🌐 Use your own full node + Electrum to avoid leaking addresses to third-party servers.',
  '⏳ Time-stamping heuristics: spending outputs too quickly reveals spending patterns — wait before consolidating.',
  '🔢 Avoid address reuse in change outputs — wallets that recycle change addresses are trivially tracked.',
  '🧅 Tor + Bitcoin Core: run your node over Tor to prevent IP-level transaction tracing.',
  '📊 Fee fingerprinting: some wallets use unique fee calculation patterns that reveal which software you use.',
  '🔑 BIP47 reusable payment codes let you receive payments without reusing addresses publicly.',
  '📐 Equal-output CoinJoins are the strongest on-chain privacy tool — outputs of the same size are indistinguishable.',
  '🛡️ The safest UTXO strategy: spend UTXOs from the same source together, never mix sources.',
]

export default function LoadingScreen({ descriptor, autoMode = false }) {
  const MESSAGES = autoMode ? MESSAGES_AUTO : MESSAGES_MANUAL
  const [msgIndex, setMsgIndex] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const [tipIndex, setTipIndex] = useState(0)
  const [tipVisible, setTipVisible] = useState(false)
  const [tipFade, setTipFade] = useState(true)

  // rotate scan status messages
  useEffect(() => {
    setMsgIndex(0)
    const msgInterval = setInterval(() => {
      setMsgIndex((i) => (i + 1) % MESSAGES.length)
    }, autoMode ? 2200 : 1000)
    return () => clearInterval(msgInterval)
  }, [autoMode])

  // elapsed timer
  useEffect(() => {
    const timerInterval = setInterval(() => {
      setElapsed((s) => s + 1)
    }, 1000)
    return () => clearInterval(timerInterval)
  }, [])

  // show tips after 10s, rotate every 5s with fade
  useEffect(() => {
    if (elapsed === 10) {
      setTipIndex(0)
      setTipFade(true)
      setTipVisible(true)
    }
    if (elapsed > 10 && (elapsed - 10) % 5 === 0) {
      // fade out, then change tip, then fade in
      setTipFade(false)
      setTimeout(() => {
        setTipIndex((i) => (i + 1) % PRIVACY_TIPS.length)
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
    ? elapsed >= 15 ? ' — auto-scanning, checking gap limit...'
      : elapsed >= 5 ? ' — scanning batches'
      : ''
    : elapsed >= 10 ? ' — large wallet, please wait' : ''

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
          <div className={styles.autoModeBadge}>⚡ Auto gap-limit scan</div>
        )}
        <div key={msgIndex} className={styles.statusText}>
          {MESSAGES[msgIndex]}<span className={styles.dots}>...</span>
        </div>
        <div className={styles.descriptor}>{shortDescriptor}</div>
        <div className={styles.timer}>
          <span className={styles.timerIcon}>⏱</span>
          {formatTime(elapsed)}
          {slowNote && (
            <span className={styles.timerNote}>{slowNote}</span>
          )}
        </div>
      </div>

      <div className={styles.progressBar}>
        <div className={styles.progressFill} />
      </div>

      {tipVisible && (
        <div
          className={styles.tipBox}
          style={{ opacity: tipFade ? 1 : 0, transition: 'opacity 0.4s ease' }}
        >
          <div className={styles.tipLabel}>Privacy tip</div>
          <div className={styles.tipText}>{PRIVACY_TIPS[tipIndex]}</div>
          <div className={styles.tipCounter}>{tipIndex + 1} / {PRIVACY_TIPS.length}</div>
        </div>
      )}
    </div>
  )
}
