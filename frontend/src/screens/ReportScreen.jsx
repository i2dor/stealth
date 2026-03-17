import FindingCard from '../components/FindingCard'
import styles from './ReportScreen.module.css'

function truncateDescriptor(desc) {
  if (!desc || desc.length <= 80) return desc
  return `${desc.slice(0, 80)}…`
}

export default function ReportScreen({
  report,
  aggregateReport,
  descriptor,
  success,
  onReset,
  onScanNext,
  onScanPrevious,
}) {
  const currentWindow = report?.scan_window || {}
  const aggregate = aggregateReport || report || {}

  const stats = aggregate?.stats || {}
  const findings = aggregate?.findings || []
  const warnings = aggregate?.warnings || []
  const summary = aggregate?.summary || {}
  const aggregateWindow = aggregate?.aggregate_scan_window || {}

  const fromIndex = currentWindow?.from_index ?? 0
  const toIndex = currentWindow?.to_index ?? 0
  const totalFrom = aggregateWindow?.from_index ?? fromIndex
  const totalTo = aggregateWindow?.to_index ?? toIndex
  const isFirstBatch = fromIndex <= 0

  return (
    <div className={styles.root}>
      <div className={styles.container}>
        <div className={styles.header}>
          <div className={styles.nav}>
            <div className={styles.wordmark}>
              STEAL<span>TH</span>
            </div>
            <button className={styles.backButton} onClick={onReset}>
              ← Analyze Another Wallet
            </button>
          </div>

          <div className={styles.descriptorBox}>
            <span className={styles.descriptorLabel}>Analyzed descriptor</span>
            <div className={styles.descriptorValue}>
              {truncateDescriptor(descriptor)}
            </div>
          </div>
        </div>

        {success && (
          <div className={styles.successBanner}>
            <span className={styles.successIcon}>✓</span>
            <span>{success}</span>
          </div>
        )}

        <div className={styles.scanMeta}>
          Current batch: {fromIndex}–{toIndex}
        </div>

        <div className={styles.scanMeta}>
          Total scanned so far: {totalFrom}–{totalTo}
        </div>

        <div className={styles.paginationRow}>
          <button
            className={styles.moreButton}
            onClick={onScanPrevious}
            disabled={isFirstBatch}
          >
            Previous 100
          </button>

          <button
            className={styles.moreButton}
            onClick={onScanNext}
          >
            Scan next 100
          </button>
        </div>

        <div className={styles.summaryBar}>
          <div className={`${styles.summaryCard} ${styles.vulnerable}`}>
            <div className={styles.summaryNumber}>{summary.findings || 0}</div>
            <div className={styles.summaryLabel}>Findings</div>
          </div>

          <div className={`${styles.summaryCard} ${styles.warn}`}>
            <div className={styles.summaryNumber}>{summary.warnings || 0}</div>
            <div className={styles.summaryLabel}>Warnings</div>
          </div>

          <div className={`${styles.summaryCard} ${styles.total}`}>
            <div className={styles.summaryNumber}>
              {stats.transactions_analyzed || 0}
            </div>
            <div className={styles.summaryLabel}>Txs Analyzed</div>
          </div>
        </div>

        {summary.clean && (
          <div className={styles.cleanBanner}>
            No privacy issues found — this wallet has a clean history.
          </div>
        )}

        {findings.length > 0 && (
          <>
            <div className={styles.listHeader}>
              <span className={styles.listTitle}>All Findings So Far</span>
            </div>
            <div className={styles.findingList}>
              {findings.map((f, i) => (
                <FindingCard key={f.id || `${f.type || 'f'}-${i}`} finding={f} />
              ))}
            </div>
          </>
        )}

        {warnings.length > 0 && (
          <>
            <div className={styles.listHeader} style={{ marginTop: 28 }}>
              <span className={styles.listTitle}>All Warnings So Far</span>
            </div>
            <div className={styles.findingList}>
              {warnings.map((w, i) => (
                <FindingCard key={w.id || `${w.type || 'w'}-${i}`} finding={w} />
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
