import FindingCard from '../components/FindingCard'
import styles from './ReportScreen.module.css'

function truncateDescriptor(desc) {
  if (!desc || desc.length <= 80) return desc
  return `${desc.slice(0, 80)}\u2026`
}

function exportJSON(aggregateReport, descriptor) {
  const payload = {
    exported_at: new Date().toISOString(),
    descriptor_hint: descriptor ? `${descriptor.slice(0, 20)}...` : 'n/a',
    ...aggregateReport,
  }
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `stealth-report-${Date.now()}.json`
  a.click()
  URL.revokeObjectURL(url)
}

function exportPDF(aggregateReport, descriptor) {
  const stats = aggregateReport?.stats || {}
  const findings = aggregateReport?.findings || []
  const warnings = aggregateReport?.warnings || []
  const window_ = aggregateReport?.aggregate_scan_window || {}

  const lines = []
  lines.push('STEALTH — Bitcoin Wallet Privacy Report')
  lines.push('=' .repeat(60))
  lines.push(`Generated: ${new Date().toLocaleString()}`)
  lines.push(`Descriptor: ${descriptor ? descriptor.slice(0, 60) + '...' : 'n/a'}`)
  lines.push(`Addresses scanned: ${window_.from_index ?? 0} – ${window_.to_index ?? 0}`)
  lines.push(`Transactions analyzed: ${stats.transactions_analyzed || 0}`)
  lines.push('')
  lines.push(`SUMMARY: ${findings.length} finding(s), ${warnings.length} warning(s)`)
  lines.push('')

  if (findings.length > 0) {
    lines.push('FINDINGS')
    lines.push('-'.repeat(40))
    findings.forEach((f, i) => {
      lines.push(`${i + 1}. [${f.severity}] ${f.type} — ${f.description}`)
      if (f.correction) lines.push(`   Fix: ${f.correction}`)
    })
    lines.push('')
  }

  if (warnings.length > 0) {
    lines.push('WARNINGS')
    lines.push('-'.repeat(40))
    warnings.forEach((w, i) => {
      lines.push(`${i + 1}. [${w.severity}] ${w.type} — ${w.description}`)
    })
    lines.push('')
  }

  const content = lines.join('\n')
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `stealth-report-${Date.now()}.txt`
  a.click()
  URL.revokeObjectURL(url)
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
            <div className={styles.navActions}>
              <button
                className={styles.exportButton}
                onClick={() => exportJSON(aggregate, descriptor)}
                title="Export JSON report"
              >
                ↓ JSON
              </button>
              <button
                className={styles.exportButton}
                onClick={() => exportPDF(aggregate, descriptor)}
                title="Export text report"
              >
                ↓ TXT
              </button>
              <button className={styles.backButton} onClick={onReset}>
                ← Analyze Another
              </button>
            </div>
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
          Current batch: addresses {fromIndex}–{toIndex}
        </div>

        <div className={styles.scanMeta}>
          All addresses scanned: {totalFrom}–{totalTo}
        </div>

        <div className={styles.paginationRow}>
          <button
            className={styles.moreButton}
            onClick={onScanPrevious}
            disabled={isFirstBatch}
          >
            ← Previous batch
          </button>

          <button
            className={styles.moreButton}
            onClick={onScanNext}
          >
            Next batch →
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
