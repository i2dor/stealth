import { useState } from 'react'
import InputScreen from './screens/InputScreen'
import LoadingScreen from './screens/LoadingScreen'
import ReportScreen from './screens/ReportScreen'
import { analyzeWallet } from './services/walletService'

const SCAN_BATCH_SIZE = 60

function dedupeByKey(items = [], getKey) {
  const map = new Map()
  for (const item of items) {
    const key = getKey(item)
    if (!map.has(key)) map.set(key, item)
  }
  return Array.from(map.values())
}

function findingKey(item) {
  const txid = item.txid || item.details?.txid || ''
  const address = item.address || item.details?.address || ''
  return item.id || `${item.type || 'finding'}::${address}::${txid}::${item.description || ''}`
}

function mergeAggregateReports(prevAggregate, newReport) {
  if (!newReport) return prevAggregate

  const findings = dedupeByKey(
    [...(prevAggregate?.findings || []), ...(newReport?.findings || [])],
    findingKey
  )
  const warnings = dedupeByKey(
    [...(prevAggregate?.warnings || []), ...(newReport?.warnings || [])],
    findingKey
  )

  const prevTxs = prevAggregate?.stats?.transactions_analyzed || 0
  const newTxs = newReport?.stats?.transactions_analyzed || 0
  const prevFrom = prevAggregate?.aggregate_scan_window?.from_index
  const prevTo = prevAggregate?.aggregate_scan_window?.to_index
  const newFrom = newReport?.scan_window?.from_index
  const newTo = newReport?.scan_window?.to_index

  return {
    stats: { transactions_analyzed: prevTxs + newTxs },
    findings,
    warnings,
    summary: {
      findings: findings.length,
      warnings: warnings.length,
      clean: findings.length === 0 && warnings.length === 0,
    },
    aggregate_scan_window: {
      from_index: prevFrom === undefined ? (newFrom ?? 0) : Math.min(prevFrom, newFrom ?? prevFrom),
      to_index: prevTo === undefined ? (newTo ?? 0) : Math.max(prevTo, newTo ?? prevTo),
    },
  }
}

export default function App() {
  const [screen, setScreen] = useState('input')
  const [descriptor, setDescriptor] = useState('')
  const [scanOptions, setScanOptions] = useState({ branch: 'receive', auto: false })
  const [currentReport, setCurrentReport] = useState(null)
  const [aggregateReport, setAggregateReport] = useState(null)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [offset, setOffset] = useState(0)
  const [reportCache, setReportCache] = useState({})

  async function loadBatch(desc, nextOffset = 0, options = { extendAggregate: true }, scanOpts) {
    setDescriptor(desc)
    setError('')
    setSuccess('')

    const opts = scanOpts || scanOptions
    const cacheKey = `${desc}::${nextOffset}::${opts.branch}::${opts.auto}`
    const cachedReport = reportCache[cacheKey]

    if (cachedReport) {
      setCurrentReport(cachedReport)
      setOffset(nextOffset)
      const hasIssues = (aggregateReport?.findings?.length || 0) > 0 || (aggregateReport?.warnings?.length || 0) > 0
      setSuccess(hasIssues ? '' : 'Scan complete — no issues found.')
      setScreen('report')
      return
    }

    setScreen('loading')

    try {
      const result = await analyzeWallet(desc, nextOffset, SCAN_BATCH_SIZE, opts)

      console.log('Scan offset:', nextOffset, 'opts:', opts)
      console.log('Result:', result)

      let computedAggregate = aggregateReport
      if (options.extendAggregate) {
        computedAggregate = mergeAggregateReports(aggregateReport, result)
      }

      setReportCache((prev) => ({ ...prev, [cacheKey]: result }))
      setCurrentReport(result)
      setAggregateReport(computedAggregate)
      setOffset(nextOffset)

      const hasIssues = (computedAggregate?.findings?.length || 0) > 0 || (computedAggregate?.warnings?.length || 0) > 0
      setSuccess(hasIssues ? '' : 'Scan complete — no issues found.')
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

  async function handleAnalyze(desc, opts) {
    setScanOptions(opts)
    setReportCache({})
    setAggregateReport(null)
    setCurrentReport(null)
    setOffset(0)
    await loadBatch(desc, 0, { extendAggregate: true }, opts)
  }

  async function handleScanNext() {
    await loadBatch(descriptor, offset + SCAN_BATCH_SIZE, { extendAggregate: true })
  }

  async function handleScanPrevious() {
    const previousOffset = Math.max(0, offset - SCAN_BATCH_SIZE)
    const cacheKey = `${descriptor}::${previousOffset}::${scanOptions.branch}::${scanOptions.auto}`
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
    return <LoadingScreen descriptor={descriptor} autoMode={scanOptions.auto} />
  }

  if (screen === 'report') {
    return (
      <ReportScreen
        report={currentReport}
        aggregateReport={aggregateReport}
        descriptor={descriptor}
        scanOptions={scanOptions}
        offset={offset}
        success={success}
        onReset={handleReset}
        onScanNext={handleScanNext}
        onScanPrevious={handleScanPrevious}
      />
    )
  }

  return <InputScreen onAnalyze={handleAnalyze} error={error} />
}
