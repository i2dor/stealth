import { useState } from 'react'
import InputScreen from './screens/InputScreen'
import LoadingScreen from './screens/LoadingScreen'
import ReportScreen from './screens/ReportScreen'
import { analyzeWallet } from './services/walletService'

const SCAN_BATCH_SIZE = 100

function dedupeByKey(items = [], getKey) {
  const map = new Map()

  for (const item of items) {
    const key = getKey(item)
    if (!map.has(key)) {
      map.set(key, item)
    }
  }

  return Array.from(map.values())
}

function buildAggregateReport(cache, descriptor) {
  const entries = Object.entries(cache)
    .filter(([key]) => key.startsWith(`${descriptor}::`))
    .sort((a, b) => {
      const offsetA = Number(a[0].split('::')[1] || 0)
      const offsetB = Number(b[0].split('::')[1] || 0)
      return offsetA - offsetB
    })

  if (entries.length === 0) return null

  const reports = entries.map(([, value]) => value)

  const allFindings = reports.flatMap((r) => r?.findings || [])
  const allWarnings = reports.flatMap((r) => r?.warnings || [])

  const findings = dedupeByKey(
    allFindings,
    (item) =>
      item.id ||
      `${item.type || 'finding'}::${item.address || ''}::${item.txid || ''}::${item.message || ''}`
  )

  const warnings = dedupeByKey(
    allWarnings,
    (item) =>
      item.id ||
      `${item.type || 'warning'}::${item.address || ''}::${item.txid || ''}::${item.message || ''}`
  )

  const transactionsAnalyzed = reports.reduce(
    (sum, r) => sum + (r?.stats?.transactions_analyzed || 0),
    0
  )

  const firstWindow = reports[0]?.scan_window
  const lastWindow = reports[reports.length - 1]?.scan_window

  return {
    stats: {
      transactions_analyzed: transactionsAnalyzed,
    },
    findings,
    warnings,
    summary: {
      findings: findings.length,
      warnings: warnings.length,
      clean: findings.length === 0 && warnings.length === 0,
    },
    aggregate_scan_window: {
      from_index: firstWindow?.from_index ?? 0,
      to_index: lastWindow?.to_index ?? 0,
    },
  }
}

export default function App() {
  const [screen, setScreen] = useState('input')
  const [descriptor, setDescriptor] = useState('')
  const [report, setReport] = useState(null)
  const [aggregateReport, setAggregateReport] = useState(null)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [offset, setOffset] = useState(0)
  const [reportCache, setReportCache] = useState({})

  async function runAnalysis(desc, nextOffset = 0) {
    setDescriptor(desc)
    setError('')
    setSuccess('')

    const cacheKey = `${desc}::${nextOffset}`

    if (reportCache[cacheKey]) {
      const cachedReport = reportCache[cacheKey]
      const nextAggregate = buildAggregateReport(reportCache, desc)

      setReport(cachedReport)
      setAggregateReport(nextAggregate)
      setOffset(nextOffset)

      const hasIssues =
        (nextAggregate?.findings?.length || 0) > 0 ||
        (nextAggregate?.warnings?.length || 0) > 0

      setSuccess(hasIssues ? '' : 'Wallet analysis completed successfully.')
      setScreen('report')
      return
    }

    setScreen('loading')

    try {
      const result = await analyzeWallet(desc, nextOffset, SCAN_BATCH_SIZE)

      const nextCache = {
        ...reportCache,
        [cacheKey]: result,
      }

      const nextAggregate = buildAggregateReport(nextCache, desc)

      setReport(result)
      setAggregateReport(nextAggregate)
      setOffset(nextOffset)
      setReportCache(nextCache)

      const hasIssues =
        (nextAggregate?.findings?.length || 0) > 0 ||
        (nextAggregate?.warnings?.length || 0) > 0

      setSuccess(hasIssues ? '' : 'Wallet analysis completed successfully.')
      setScreen('report')
    } catch (err) {
      console.error('Analysis failed:', err)
      setReport(null)
      setAggregateReport(null)
      setSuccess('')
      setError(err.message || 'Analysis failed. Please try again.')
      setScreen('input')
    }
  }

  async function handleAnalyze(desc) {
    setReportCache({})
    setAggregateReport(null)
    await runAnalysis(desc, 0)
  }

  async function handleScanNext() {
    await runAnalysis(descriptor, offset + SCAN_BATCH_SIZE)
  }

  async function handleScanPrevious() {
    const previousOffset = Math.max(0, offset - SCAN_BATCH_SIZE)
    await runAnalysis(descriptor, previousOffset)
  }

  function handleReset() {
    setScreen('input')
    setDescriptor('')
    setReport(null)
    setAggregateReport(null)
    setError('')
    setSuccess('')
    setOffset(0)
    setReportCache({})
  }

  if (screen === 'loading') {
    return <LoadingScreen descriptor={descriptor} />
  }

  if (screen === 'report') {
    return (
      <ReportScreen
        report={report}
        aggregateReport={aggregateReport}
        descriptor={descriptor}
        success={success}
        onReset={handleReset}
        onScanNext={handleScanNext}
        onScanPrevious={handleScanPrevious}
      />
    )
  }

  return (
    <InputScreen
      onAnalyze={handleAnalyze}
      error={error}
    />
  )
}
