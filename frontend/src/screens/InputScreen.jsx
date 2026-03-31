import { useState } from 'react'
import styles from './InputScreen.module.css'

const PLACEHOLDER = `wpkh([a1b2c3d4/84h/0h/0h]xpub6CatWdiZynkCminahu8Gmr7FAVnQXBTSMaBxn6qmBNkdm9tDkFzWmjmDrLBCQSTa7BHgpEjCXzMTCyDsQLSmcGYJHBB7cTwpqLNRKGP47uw/0/*)#qwer1234`

export default function InputScreen({ onAnalyze, error, success }) {
  const [descriptor, setDescriptor] = useState('')
  const isHttps = typeof window !== 'undefined' && window.location.protocol === 'https:'
  const isLocalhost = typeof window !== 'undefined' &&
    (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  const showHttpsWarning = !isHttps && !isLocalhost

  function handleSubmit(e) {
    e.preventDefault()
    const trimmed = descriptor.trim()
    if (!trimmed) return
    onAnalyze(trimmed)
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

          {error && <div className={styles.errorBox}>{error}</div>}
          {success && <div className={styles.successBox}>{success}</div>}

          <button
            type="submit"
            className={styles.button}
            disabled={!descriptor.trim()}
          >
            Analyze Wallet
          </button>

          <p className={styles.hint}>
            Supports <code>wpkh()</code>, <code>pkh()</code>, <code>sh(wpkh())</code> descriptors
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
