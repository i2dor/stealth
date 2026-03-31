import { useState, useEffect } from 'react'
import styles from './LoadingScreen.module.css'

const MESSAGES = [
  'Resolving descriptors',
  'Deriving addresses',
  'Importing & scanning blockchain',
  'Loading transaction history',
  'Running vulnerability detectors',
]

export default function LoadingScreen({ descriptor }) {
  const [msgIndex, setMsgIndex] = useState(0)
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    const msgInterval = setInterval(() => {
      setMsgIndex((i) => (i + 1) % MESSAGES.length)
    }, 1000)
    return () => clearInterval(msgInterval)
  }, [])

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
        <div key={msgIndex} className={styles.statusText}>
          {MESSAGES[msgIndex]}<span className={styles.dots}>...</span>
        </div>
        <div className={styles.descriptor}>{shortDescriptor}</div>
        <div className={styles.timer}>
          <span className={styles.timerIcon}>⏱</span>
          {formatTime(elapsed)}
          {elapsed >= 10 && (
            <span className={styles.timerNote}> — large wallet, please wait</span>
          )}
        </div>
      </div>

      <div className={styles.progressBar}>
        <div className={styles.progressFill} />
      </div>
    </div>
  )
}
