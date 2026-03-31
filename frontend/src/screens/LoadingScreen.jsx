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

export default function LoadingScreen({ descriptor, autoMode = false }) {
  const MESSAGES = autoMode ? MESSAGES_AUTO : MESSAGES_MANUAL
  const [msgIndex, setMsgIndex] = useState(0)
  const [elapsed, setElapsed] = useState(0)

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
    </div>
  )
}
