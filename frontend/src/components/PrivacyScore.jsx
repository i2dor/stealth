import styles from './PrivacyScore.module.css'

const GRADE_COLORS = {
  A: 'var(--accent)',
  B: '#4ade80',
  C: 'var(--warning)',
  D: '#ff8c42',
  F: 'var(--danger)',
}

export default function PrivacyScore({ data }) {
  if (!data) return null

  const { score, grade, label, severity_breakdown } = data
  const color = GRADE_COLORS[grade] || 'var(--text-muted)'
  const radius = 54
  const stroke = 7
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  const hasCritical = (severity_breakdown?.CRITICAL || 0) > 0
  const hasHigh = (severity_breakdown?.HIGH || 0) > 0

  return (
    <div className={styles.wrapper}>
      <div className={styles.gauge}>
        <svg viewBox="0 0 128 128" className={styles.ring}>
          <circle
            cx="64" cy="64" r={radius}
            fill="none"
            stroke="var(--border)"
            strokeWidth={stroke}
          />
          <circle
            cx="64" cy="64" r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            transform="rotate(-90 64 64)"
            className={styles.progress}
          />
        </svg>
        <div className={styles.center}>
          <span className={styles.score} style={{ color }}>{score}</span>
          <span className={styles.grade} style={{ color }}>{grade}</span>
        </div>
      </div>
      <div className={styles.info}>
        <div className={styles.label}>{label}</div>
        <div className={styles.breakdown}>
          {hasCritical && <span className={styles.tagCritical}>{severity_breakdown.CRITICAL} critical</span>}
          {hasHigh && <span className={styles.tagHigh}>{severity_breakdown.HIGH} high</span>}
          {(severity_breakdown?.MEDIUM || 0) > 0 && <span className={styles.tagMedium}>{severity_breakdown.MEDIUM} medium</span>}
          {(severity_breakdown?.LOW || 0) > 0 && <span className={styles.tagLow}>{severity_breakdown.LOW} low</span>}
        </div>
      </div>
    </div>
  )
}
