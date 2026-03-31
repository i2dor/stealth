import { useState } from 'react'
import styles from './SettingsScreen.module.css'

const DEFAULTS = {
  apiBase: '',
  blockstreamUrl: 'https://blockstream.info/api',
  mempoolUrl: 'https://mempool.space/api',
  electrumHost: '',
  electrumPort: '50002',
  electrumSsl: true,
  requestDelay: '300',
  scanBatchSize: '60',
  gapLimit: '20',
  torProxy: '',
}

export default function SettingsScreen({ settings, onSave, onBack }) {
  const [form, setForm] = useState({ ...DEFAULTS, ...settings })
  const [saved, setSaved] = useState(false)

  function set(key, value) {
    setForm((f) => ({ ...f, [key]: value }))
    setSaved(false)
  }

  function handleSave(e) {
    e.preventDefault()
    onSave(form)
    setSaved(true)
  }

  function handleReset() {
    setForm({ ...DEFAULTS })
    setSaved(false)
  }

  return (
    <div className={styles.root}>
      <div className={styles.container}>
        <div className={styles.header}>
          <button className={styles.backBtn} onClick={onBack}>
            \u2190 Back
          </button>
          <div className={styles.titleRow}>
            <span className={styles.wordmark}>STEAL<span>TH</span></span>
            <span className={styles.pageTitle}>Settings</span>
          </div>
        </div>

        <form onSubmit={handleSave}>

          {/* API / Backend */}
          <section className={styles.section}>
            <div className={styles.sectionHeader}>
              <span className={styles.sectionIcon}>\ud83d\udce1</span>
              <div>
                <div className={styles.sectionTitle}>API & Backend</div>
                <div className={styles.sectionDesc}>Configure which API the app uses for blockchain data</div>
              </div>
            </div>

            <div className={styles.field}>
              <label className={styles.label}>Backend API base URL</label>
              <div className={styles.fieldDesc}>Leave empty to use the default Vercel API. Set a custom URL to use your own backend.</div>
              <input
                className={styles.input}
                type="text"
                placeholder="https://your-backend.example.com"
                value={form.apiBase}
                onChange={(e) => set('apiBase', e.target.value)}
                spellCheck={false}
              />
            </div>

            <div className={styles.field}>
              <label className={styles.label}>Blockstream API URL</label>
              <div className={styles.fieldDesc}>Used for address and transaction lookups</div>
              <input
                className={styles.input}
                type="text"
                value={form.blockstreamUrl}
                onChange={(e) => set('blockstreamUrl', e.target.value)}
                spellCheck={false}
              />
            </div>

            <div className={styles.field}>
              <label className={styles.label}>Mempool.space API URL</label>
              <div className={styles.fieldDesc}>Used as fallback and for fee/mempool data</div>
              <input
                className={styles.input}
                type="text"
                value={form.mempoolUrl}
                onChange={(e) => set('mempoolUrl', e.target.value)}
                spellCheck={false}
              />
            </div>
          </section>

          {/* Own Node */}
          <section className={styles.section}>
            <div className={styles.sectionHeader}>
              <span className={styles.sectionIcon}>\u26a1</span>
              <div>
                <div className={styles.sectionTitle}>Own Node (Electrum)</div>
                <div className={styles.sectionDesc}>Connect to your own Electrum server for maximum privacy</div>
              </div>
            </div>

            <div className={styles.infoBox}>
              <span>\ud83d\udd12</span>
              <span>Connecting to your own Electrum server means your addresses are never sent to a third-party. Run <code>electrs</code>, <code>Fulcrum</code>, or <code>ElectrumX</code> locally or on your home server.</span>
            </div>

            <div className={styles.fieldRow}>
              <div className={styles.field} style={{flex: 3}}>
                <label className={styles.label}>Electrum host</label>
                <input
                  className={styles.input}
                  type="text"
                  placeholder="127.0.0.1 or yourdomain.onion"
                  value={form.electrumHost}
                  onChange={(e) => set('electrumHost', e.target.value)}
                  spellCheck={false}
                />
              </div>
              <div className={styles.field} style={{flex: 1}}>
                <label className={styles.label}>Port</label>
                <input
                  className={styles.input}
                  type="number"
                  min="1"
                  max="65535"
                  value={form.electrumPort}
                  onChange={(e) => set('electrumPort', e.target.value)}
                />
              </div>
            </div>

            <div className={styles.field}>
              <label className={styles.checkLabel}>
                <input
                  type="checkbox"
                  className={styles.checkbox}
                  checked={form.electrumSsl}
                  onChange={(e) => set('electrumSsl', e.target.checked)}
                />
                Use SSL/TLS
              </label>
            </div>
          </section>

          {/* Tor */}
          <section className={styles.section}>
            <div className={styles.sectionHeader}>
              <span className={styles.sectionIcon}>\ud83e\uddc5</span>
              <div>
                <div className={styles.sectionTitle}>Tor / Proxy</div>
                <div className={styles.sectionDesc}>Route API requests through a SOCKS5 proxy for IP privacy</div>
              </div>
            </div>

            <div className={styles.infoBox}>
              <span>\u2139\ufe0f</span>
              <span>The backend (Python/Vercel) must support SOCKS5 proxying. Set this to <code>socks5://127.0.0.1:9050</code> if running the backend locally with Tor Browser or the Tor daemon active.</span>
            </div>

            <div className={styles.field}>
              <label className={styles.label}>SOCKS5 proxy URL</label>
              <input
                className={styles.input}
                type="text"
                placeholder="socks5://127.0.0.1:9050"
                value={form.torProxy}
                onChange={(e) => set('torProxy', e.target.value)}
                spellCheck={false}
              />
            </div>
          </section>

          {/* Scan behaviour */}
          <section className={styles.section}>
            <div className={styles.sectionHeader}>
              <span className={styles.sectionIcon}>\u2699\ufe0f</span>
              <div>
                <div className={styles.sectionTitle}>Scan Behaviour</div>
                <div className={styles.sectionDesc}>Tune performance and scanning parameters</div>
              </div>
            </div>

            <div className={styles.fieldRow}>
              <div className={styles.field}>
                <label className={styles.label}>Request delay (ms)</label>
                <div className={styles.fieldDesc}>Delay between Blockstream/Mempool requests to avoid rate-limiting</div>
                <input
                  className={styles.input}
                  type="number"
                  min="0"
                  max="5000"
                  step="50"
                  value={form.requestDelay}
                  onChange={(e) => set('requestDelay', e.target.value)}
                />
              </div>

              <div className={styles.field}>
                <label className={styles.label}>Batch size</label>
                <div className={styles.fieldDesc}>Addresses per scan batch</div>
                <input
                  className={styles.input}
                  type="number"
                  min="10"
                  max="200"
                  step="10"
                  value={form.scanBatchSize}
                  onChange={(e) => set('scanBatchSize', e.target.value)}
                />
              </div>

              <div className={styles.field}>
                <label className={styles.label}>Gap limit</label>
                <div className={styles.fieldDesc}>Consecutive empty addresses before stopping (BIP44: 20)</div>
                <input
                  className={styles.input}
                  type="number"
                  min="5"
                  max="100"
                  value={form.gapLimit}
                  onChange={(e) => set('gapLimit', e.target.value)}
                />
              </div>
            </div>
          </section>

          <div className={styles.actions}>
            <button type="button" className={styles.resetBtn} onClick={handleReset}>
              Reset to defaults
            </button>
            <button type="submit" className={styles.saveBtn}>
              {saved ? '\u2713 Saved' : 'Save settings'}
            </button>
          </div>

        </form>
      </div>
    </div>
  )
}
