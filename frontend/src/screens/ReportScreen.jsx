import { useRef } from 'react'
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

async function exportPDF(aggregateReport, descriptor) {
  // Dynamically load jsPDF from CDN
  if (!window.jspdf) {
    await new Promise((resolve, reject) => {
      const script = document.createElement('script')
      script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js'
      script.onload = resolve
      script.onerror = reject
      document.head.appendChild(script)
    })
  }

  const { jsPDF } = window.jspdf
  const doc = new jsPDF({ unit: 'pt', format: 'a4' })

  const PAGE_W = doc.internal.pageSize.getWidth()
  const PAGE_H = doc.internal.pageSize.getHeight()
  const MARGIN = 48
  const CONTENT_W = PAGE_W - MARGIN * 2
  let y = MARGIN

  const COLORS = {
    bg:       [15, 15, 18],
    accent:   [0, 212, 170],
    danger:   [255, 77, 109],
    warning:  [244, 162, 97],
    success:  [74, 222, 128],
    muted:    [120, 120, 130],
    text:     [220, 220, 225],
    white:    [255, 255, 255],
    divider:  [40, 40, 50],
    criticalBg: [74, 16, 16],
    highBg:   [61, 26, 26],
    mediumBg: [46, 34,  8],
    lowBg:    [15, 40, 24],
    infoBg:   [17, 24, 39],
  }

  const SEVERITY_COLORS = {
    CRITICAL: { bg: COLORS.criticalBg, text: [255, 107, 107] },
    HIGH:     { bg: COLORS.highBg,     text: [248, 113, 113] },
    MEDIUM:   { bg: COLORS.mediumBg,   text: [251, 191,  36] },
    LOW:      { bg: COLORS.lowBg,      text: [ 74, 222, 128] },
    INFO:     { bg: COLORS.infoBg,     text: [148, 163, 184] },
  }

  function newPageIfNeeded(needed = 40) {
    if (y + needed > PAGE_H - MARGIN) {
      doc.addPage()
      // dark bg for new page
      doc.setFillColor(...COLORS.bg)
      doc.rect(0, 0, PAGE_W, PAGE_H, 'F')
      y = MARGIN
      return true
    }
    return false
  }

  function hline(color = COLORS.divider) {
    newPageIfNeeded(8)
    doc.setDrawColor(...color)
    doc.setLineWidth(0.5)
    doc.line(MARGIN, y, PAGE_W - MARGIN, y)
    y += 10
  }

  function text(str, x, size, color, opts = {}) {
    doc.setFontSize(size)
    doc.setTextColor(...color)
    const lines = doc.splitTextToSize(String(str), opts.maxWidth || CONTENT_W)
    doc.text(lines, x, y, opts)
    return lines.length
  }

  // ── DARK BACKGROUND (page 1) ──────────────────────────────
  doc.setFillColor(...COLORS.bg)
  doc.rect(0, 0, PAGE_W, PAGE_H, 'F')

  // ── HEADER BAND ───────────────────────────────────────────
  doc.setFillColor(0, 180, 145)
  doc.rect(0, 0, PAGE_W, 6, 'F')

  y = 42
  doc.setFontSize(22)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(...COLORS.white)
  doc.text('STEAL', MARGIN, y)
  const stealW = doc.getTextWidth('STEAL')
  doc.setTextColor(...COLORS.accent)
  doc.text('TH', MARGIN + stealW, y)

  doc.setFontSize(10)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(...COLORS.muted)
  doc.text('Bitcoin Wallet Privacy Report', MARGIN, y + 16)
  doc.text(`Generated: ${new Date().toLocaleString()}`, PAGE_W - MARGIN, y + 16, { align: 'right' })

  y = 90
  hline(COLORS.accent)

  // ── DESCRIPTOR ────────────────────────────────────────────
  const stats = aggregateReport?.stats || {}
  const findings = aggregateReport?.findings || []
  const warnings = aggregateReport?.warnings || []
  const window_ = aggregateReport?.aggregate_scan_window || {}

  doc.setFontSize(8)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(...COLORS.muted)
  doc.text('DESCRIPTOR', MARGIN, y)
  y += 12
  doc.setFont('courier', 'normal')
  doc.setFontSize(9)
  doc.setTextColor(...COLORS.text)
  const descStr = descriptor ? (descriptor.length > 100 ? descriptor.slice(0, 100) + '…' : descriptor) : 'n/a'
  const descLines = doc.splitTextToSize(descStr, CONTENT_W)
  doc.text(descLines, MARGIN, y)
  y += descLines.length * 12 + 14

  // ── SCAN WINDOW ───────────────────────────────────────────
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(9)
  doc.setTextColor(...COLORS.muted)
  doc.text(`Addresses scanned: ${window_.from_index ?? 0} – ${window_.to_index ?? 0}`, MARGIN, y)
  doc.text(`Transactions analyzed: ${stats.transactions_analyzed || 0}`, MARGIN + 180, y)
  doc.text(`UTXOs found: ${stats.utxos_found || 0}`, MARGIN + 360, y)
  y += 22

  hline()

  // ── SUMMARY BOXES ─────────────────────────────────────────
  const boxW = (CONTENT_W - 16) / 3
  const boxes = [
    { label: 'Findings', value: findings.length, color: findings.length > 0 ? COLORS.danger : COLORS.accent },
    { label: 'Warnings', value: warnings.length, color: warnings.length > 0 ? COLORS.warning : COLORS.muted },
    { label: 'Txs Analyzed', value: stats.transactions_analyzed || 0, color: COLORS.text },
  ]
  boxes.forEach((box, i) => {
    const bx = MARGIN + i * (boxW + 8)
    doc.setFillColor(25, 25, 32)
    doc.roundedRect(bx, y, boxW, 48, 4, 4, 'F')
    doc.setFontSize(22)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(...box.color)
    doc.text(String(box.value), bx + boxW / 2, y + 26, { align: 'center' })
    doc.setFontSize(8)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(...COLORS.muted)
    doc.text(box.label.toUpperCase(), bx + boxW / 2, y + 40, { align: 'center' })
  })
  y += 64

  hline()

  // ── FINDINGS ──────────────────────────────────────────────
  if (findings.length > 0) {
    doc.setFontSize(11)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(...COLORS.white)
    doc.text('FINDINGS', MARGIN, y)
    y += 18

    findings.forEach((f, idx) => {
      newPageIfNeeded(60)
      const sev = f.severity || 'INFO'
      const sc = SEVERITY_COLORS[sev] || SEVERITY_COLORS.INFO

      // Card background
      doc.setFillColor(22, 22, 30)
      doc.roundedRect(MARGIN, y, CONTENT_W, 10, 2, 2, 'F')

      // Severity badge
      doc.setFillColor(...sc.bg)
      doc.roundedRect(MARGIN, y, 54, 18, 3, 3, 'F')
      doc.setFontSize(7)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(...sc.text)
      doc.text(sev, MARGIN + 27, y + 12, { align: 'center' })

      // Type label
      doc.setFontSize(8)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(...COLORS.muted)
      doc.text(f.type || '', MARGIN + 62, y + 12)

      y += 22

      // Description
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(9)
      doc.setTextColor(...COLORS.text)
      const descLines2 = doc.splitTextToSize(f.description || '', CONTENT_W - 8)
      newPageIfNeeded(descLines2.length * 12 + 20)
      doc.text(descLines2, MARGIN + 4, y)
      y += descLines2.length * 12 + 4

      // TXID if present
      const txid = f.details?.txid
      if (txid) {
        doc.setFont('courier', 'normal')
        doc.setFontSize(8)
        doc.setTextColor(...COLORS.muted)
        doc.text(`txid: ${txid}`, MARGIN + 4, y)
        y += 12
      }

      // Correction
      if (f.correction) {
        newPageIfNeeded(30)
        doc.setFont('helvetica', 'italic')
        doc.setFontSize(8)
        doc.setTextColor(0, 170, 136)
        const fixLines = doc.splitTextToSize(`Fix: ${f.correction}`, CONTENT_W - 8)
        doc.text(fixLines, MARGIN + 4, y)
        y += fixLines.length * 11 + 4
      }

      if (idx < findings.length - 1) {
        y += 6
        doc.setDrawColor(...COLORS.divider)
        doc.setLineWidth(0.3)
        doc.line(MARGIN + 4, y, PAGE_W - MARGIN - 4, y)
        y += 8
      } else {
        y += 10
      }
    })
  }

  // ── WARNINGS ──────────────────────────────────────────────
  if (warnings.length > 0) {
    newPageIfNeeded(50)
    hline()
    doc.setFontSize(11)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(...COLORS.white)
    doc.text('WARNINGS', MARGIN, y)
    y += 18

    warnings.forEach((w, idx) => {
      newPageIfNeeded(50)
      const sev = w.severity || 'LOW'
      const sc = SEVERITY_COLORS[sev] || SEVERITY_COLORS.LOW

      doc.setFillColor(...sc.bg)
      doc.roundedRect(MARGIN, y, 54, 18, 3, 3, 'F')
      doc.setFontSize(7)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(...sc.text)
      doc.text(sev, MARGIN + 27, y + 12, { align: 'center' })

      doc.setFontSize(8)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(...COLORS.muted)
      doc.text(w.type || '', MARGIN + 62, y + 12)
      y += 22

      doc.setFont('helvetica', 'normal')
      doc.setFontSize(9)
      doc.setTextColor(...COLORS.text)
      const wLines = doc.splitTextToSize(w.description || '', CONTENT_W - 8)
      doc.text(wLines, MARGIN + 4, y)
      y += wLines.length * 12 + (idx < warnings.length - 1 ? 14 : 10)
    })
  }

  // ── FOOTER ────────────────────────────────────────────────
  const totalPages = doc.internal.getNumberOfPages()
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p)
    doc.setFontSize(7)
    doc.setTextColor(...COLORS.muted)
    doc.text(
      `STEALTH — Bitcoin Wallet Privacy Analyzer  ·  stealth.vercel.app  ·  Page ${p} of ${totalPages}`,
      PAGE_W / 2,
      PAGE_H - 20,
      { align: 'center' }
    )
    doc.setFillColor(0, 180, 145)
    doc.rect(0, PAGE_H - 4, PAGE_W, 4, 'F')
  }

  doc.save(`stealth-report-${Date.now()}.pdf`)
}

export default function ReportScreen({
  report,
  aggregateReport,
  descriptor,
  offset,
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

  const isFirstBatch = (offset ?? 0) === 0

  return (
    <div className={styles.root}>
      <div className={styles.container}>
        <div className={styles.header}>
          <div className={styles.nav}>
            <button
              className={styles.wordmark}
              onClick={onReset}
              title="Back to home"
            >
              STEAL<span>TH</span>
            </button>
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
                title="Export PDF report"
              >
                ↓ PDF
              </button>
              <button className={styles.backButton} onClick={onReset}>
                ← New Analysis
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
          Current batch: addresses&nbsp;<strong>{fromIndex}–{toIndex}</strong>
          &nbsp;·&nbsp;
          Total scanned: addresses&nbsp;<strong>{totalFrom}–{totalTo}</strong>
        </div>

        <div className={styles.paginationRow}>
          <button
            className={styles.moreButton}
            onClick={onScanPrevious}
            disabled={isFirstBatch}
            title={isFirstBatch ? 'Already at first batch' : 'Go to previous batch'}
          >
            ← Previous batch
          </button>

          <button
            className={styles.moreButton}
            onClick={onScanNext}
            title="Scan next 60 addresses"
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
            No privacy issues found in this scan window.
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
