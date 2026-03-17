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

function mergeAggregateReports(prevAggregate, newReport) {
  if (!newReport) return prevAggregate

  if (!prevAggregate) {
    const findings = newReport?.findings || []
    const warnings = newReport?.warnings || []

    return {
      stats: {
        transactions_analyzed: newReport?.stats?.transactions_analyzed || 0,
      },
      findings,
      warnings,
      summary: {
        findings: findings.length,
        warnings: warnings.length,
        clean: findings.length === 0 && warnings.length === 0,
      },
      aggregate_scan_window: {
        from_index: newReport?.scan_window?.from_index ?? 0,
        to_index: newReport?.scan_window?.to_index ?? 0,
      },
    }
  }

  const findings = dedupeByKey(
    [...(prevAggregate.findings || []), ...(newReport?.findings || [])],
    (item) =>
      item.id ||
      `${item.type || 'finding'}::${item.address || ''}::${item.txid || ''}::${item.message || ''}`
  )

  const warnings = dedupeByKey(
    [...(prevAggregate.warnings || []), ...(newReport?.warnings || [])],
    (item) =>
      item.id ||
      `${item.type || 'warning'}::${item.address || ''}::${item.txid || ''}::${item.message || ''}`
  )

  return {
    stats: {
      transactions_analyzed:
        (prevAggregate?.stats?.transactions_analyzed || 0) +
        (newReport?.stats?.transactions_analyzed || 0),
    },
    findings,
    warnings,
    summary: {
      findings: findings.length,
      warnings: warnings.length,
      clean: findings.length === 0 && warnings.length === 0,
    },
    aggregate_scan_window: {
      from_index:
        Math.min(
          prevAggregate?.aggregate_scan_window?.from_index ?? Infinity,
          newReport?.scan_window?.from_index ?? Infinity
        ) || 0,
      to_index: Math.max(
        prevAggregate?.aggregate_scan_window?.to_index ?? 0,
        newReport?.scan_window?.to_index ?? 0
      ),
    },
  }
}

export default function App() {
  const [screen, setScreen] = useState('input')
  const [descriptor, setDescriptor] = useState('')
  const [currentReport, setCurrentReport] = useState(null)
  const [aggregateReport, setAggregateReport] = useState(null)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [offset, setOffset] = useState(0)
  const [reportCache, setReportCache] = useState({})

  async function loadBatch(desc, nextOffset = 0, options = { extendAggregate: true }) {
    setDescriptor(desc)
    setError('')
    setSuccess('')

    const cacheKey = `${desc}::${nextOffset}`
    const cachedReport = reportCache[cacheKey]

    if (cachedReport) {
      setCurrentReport(cachedReport)
      setOffset(nextOffset)

      const hasIssues =
        (aggregateReport?.findings?.length || 0) > 0 ||
        (aggregateReport?.warnings?.length || 0) > 0

      setSuccess(hasIssues ? '' : 'Wallet analysis completed successfully.')
      setScreen('report')
      return
    }

    setScreen('loading')

    try {
      const result = await analyzeWallet(desc, nextOffset, SCAN_BATCH_SIZE)

      const nextAggregate = options.extendAggregate
        ? mergeAggregateReports(aggregateReport, result)
        : aggregateReport

      setReportCache((prev) => ({
        ...prev,
        [cacheKey]: result,
      }))
      setCurrentReport(result)
      setAggregateReport(nextAggregate)
      setOffset(nextOffset)

      const hasIssues =
        (nextAggregate?.findings?.length || 0) > 0 ||
        (nextAggregate?.warnings?.length || 0) > 0

      setSuccess(hasIssues ? '' : 'Wallet analysis completed successfully.')
      setScreen('report')
    } catch (err) {
      console.error('Analysis failed:', err)
      setCurrentReport(null)
      setAggregateReport(null)
      setSuccess('')
      setError(err.message || 'Analysis failed. Please try again.')
      setScreen('input')
    }
  }

  async function handleAnalyze(desc) {
    setReportCache({})
    setAggregateReport(null)
    setCurrentReport(null)
    setOffset(0)
    await loadBatch(desc, 0, { extendAggregate: true })
  }

  async function handleScanNext() {
    await loadBatch(descriptor, offset + SCAN_BATCH_SIZE, { extendAggregate: true })
  }

  async function handleScanPrevious() {
    const previousOffset = Math.max(0, offset - SCAN_BATCH_SIZE)
    const cacheKey = `${descriptor}::${previousOffset}`

    if (reportCache[cacheKey]) {
      setCurrentReport(reportCache[cacheKey])
      setOffset(previousOffset)
      setScreen('report')
      return
    }

    await loadBatch(descriptor, previousOffset, { extendAggregate: false })
  }

  function handleReset() {
    setScreen('input')
    setDescriptor('')
    setCurrentReport(null)
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
        report={currentReport}
        aggregateReport={aggregateReport}
        descriptor={descriptor}
        success={success}
        onReset={handleReset}
        onScanNext={handleScanNext}
        onScanPrevious={handleScanPrevious}
      />
    )
  }

  return <InputScreen onAnalyze={handleAnalyze} error={error} />
}
