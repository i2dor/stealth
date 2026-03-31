import { useState } from 'react'
import styles from './InputScreen.module.css'

const PLACEHOLDER = `wpkh([a1b2c3d4/84h/0h/0h]xpub6CatWdiZynkCminahu8Gmr7FAVnQXBTSMaBxn6qmBNkdm9tDkFzWmjmDrLBCQSTa7BHgpEjCXzMTCyDsQLSmcGYJHBB7cTwpqLNRKGP47uw/0/*)#qwer1234`

export default function InputScreen({ onAnalyze, error }) {
  const [descriptor, setDescriptor] = useState('')
  const [branch, setBranch] = useState('receive')
  const [autoGap, setAutoGap] = useState(false)

  const isHttps = typeof window !== 'undefined' && window.location.protocol === 'https:'
  const isLocalhost = typeof window !== 'undefined' &&
    (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  const showHttpsWarning = !isHttps && !isLocalhost

  function handleSubmit(e) {
    e.preventDefault()
    const trimmed = descriptor.trim()
    if (!trimmed) return
    onAnalyze(trimmed, { branch, auto: autoGap })
  }

  return (
    <div className={styles.root}>
      <div className={styles.container}>
        <div className={styles.wordmark}>
          <div className={styles.logo}>
            STEAL<span>TH</span>
          </div>
          <div className={styles.tagline}>Bitcoin Wallet Privacy Analyzer</div>
        </div>

        {showHttpsWarning && (
          <div className={styles.httpsWarning}>
            <span className={styles.warnIcon}>⚠</span>
            <span>
              <strong>Insecure connection detected.</strong> Use HTTPS to protect your descriptor from interception.
            </span>
          </div>
        )}

        <form className={styles.card} onSubmit={handleSubmit}>
          <label className={styles.label} htmlFor="descriptor">
            Wallet Descriptor
          </label>

          <textarea
            id="descriptor"
            className={styles.textarea}
            value={descriptor}
            onChange={(e) => setDescriptor(e.target.value)}
            placeholder={PLACEHOLDER}
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
          />

          {/* Branch selector */}
          <div className={styles.optionsRow}>
            <div className={styles.optionGroup}>
              <span className={styles.optionLabel}>Branch</span>
              <div className={styles.segmented}>
                {['receive', 'change', 'both'].map((b) => (
                  <button
                    key={b}
                    type="button"
                    className={`${styles.segment} ${branch === b ? styles.segmentActive : ''}`}
                    onClick={() => setBranch(b)}
                  >
                    {b === 'receive' ? 'Receive /0' : b === 'change' ? 'Change /1' : 'Both'}
                  </button>
                ))}
              </div>
            </div>

            <div className={styles.optionGroup}>
              <span className={styles.optionLabel}>Scan mode</span>
              <button
                type="button"
                className={`${styles.toggleBtn} ${autoGap ? styles.toggleActive : ''}`}
                onClick={() => setAutoGap((v) => !v)}
                title="Auto gap-limit: scan until 20 consecutive inactive addresses (BIP44 standard)"
              >
                <span className={styles.toggleDot} />
                Auto gap-limit
              </button>
            </div>
          </div>

          {autoGap && (
            <div className={styles.autoNote}>
              ⚡ Will scan automatically until 20 consecutive inactive addresses are found (BIP44 standard). May take longer for large wallets.
            </div>
          )}

          {error && <div className={styles.errorBox}>{error}</div>}

          <button
            type="submit"
            className={styles.button}
            disabled={!descriptor.trim()}
          >
            {autoGap ? 'Auto Scan Wallet' : 'Analyze Wallet'}
          </button>

          <p className={styles.hint}>
            Supports <code>wpkh()</code> descriptors with xpub / zpub / ypub
          </p>
        </form>

        <div className={styles.privacyNotice}>
          <span className={styles.shieldIcon}>🔒</span>
          <span>
            Your descriptor is sent only to the analysis API and is <strong>never stored or logged</strong>.
            All processing happens server-side in an ephemeral context.
          </span>
        </div>
      </div>
    </div>
  )
}
