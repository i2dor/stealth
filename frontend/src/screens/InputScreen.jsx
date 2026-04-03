import { useState } from 'react'
import styles from './InputScreen.module.css'

const PLACEHOLDER = `wpkh([a1b2c3d4/84h/0h/0h]xpub6CatWdiZynkCminahu8Gmr7FAVnQXBTSMaBxn6qmBNkdm9tDkFzWmjmDrLBCQSTa7BHgpEjCXzMTCyDsQLSmcGYJHBB7cTwpqLNRKGP47uw/0/*)#qwer1234

-- also supported --
tr([a1b2c3d4/86h/0h/0h]xpub.../0/*)
sh(wpkh([a1b2c3d4/49h/0h/0h]ypub.../0/*))
pkh([a1b2c3d4/44h/0h/0h]xpub.../0/*)`

export default function InputScreen({ onAnalyze, onSettings, error }) {
  const [descriptor, setDescriptor] = useState('')
  const [branch, setBranch] = useState('receive')
  const [autoGap, setAutoGap] = useState(false)
  const [hostedDismissed, setHostedDismissed] = useState(false)

  const isHttps = typeof window !== 'undefined' && window.location.protocol === 'https:'
  const isLocalhost = typeof window !== 'undefined' &&
    (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  const isHosted = typeof window !== 'undefined' &&
    window.location.hostname.includes('vercel.app')

  const showHttpsWarning = !isHttps && !isLocalhost
  const showHostedWarning = isHosted && !hostedDismissed

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
          <div className={styles.logoRow}>
            <div className={styles.logo}>
              STEAL<span>TH</span>
            </div>
            <button
              type="button"
              className={styles.settingsBtn}
              onClick={onSettings}
              title="Settings"
              aria-label="Open settings"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="3"/>
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
              </svg>
            </button>
          </div>
          <div className={styles.tagline}>Bitcoin Wallet Privacy Analyzer</div>
        </div>

        {showHostedWarning && (
          <div className={styles.hostedWarning}>
            <div className={styles.hostedWarningLeft}>
              <span className={styles.warnIcon}>⚠</span>
              <div>
                <strong>You're using the hosted version.</strong> Your descriptor is sent to the Vercel API server — it is not stored, but it does leave your device.
                {' '}For maximum privacy, <a href="https://github.com/i2dor/stealth#running-locally" target="_blank" rel="noopener noreferrer" className={styles.hostedLink}>run Stealth locally</a> and optionally route traffic through <a href="https://github.com/i2dor/stealth#tor--proxy" target="_blank" rel="noopener noreferrer" className={styles.hostedLink}>Tor</a>.
              </div>
            </div>
            <button
              className={styles.hostedDismiss}
              onClick={() => setHostedDismissed(true)}
              aria-label="Dismiss warning"
              title="Dismiss"
            >
              ✕
            </button>
          </div>
        )}

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
            Supports <code>wpkh()</code>, <code>tr()</code>, <code>sh(wpkh())</code>,{' '}
            <code>pkh()</code> — with xpub / ypub / zpub
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
