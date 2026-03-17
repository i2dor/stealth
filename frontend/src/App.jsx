import { useState } from 'react'
import InputScreen from './screens/InputScreen'
import LoadingScreen from './screens/LoadingScreen'
import ReportScreen from './screens/ReportScreen'
import { analyzeWallet } from './services/walletService'

const SCAN_BATCH_SIZE = 100

export default function App() {
  const [screen, setScreen] = useState('input')
  const [descriptor, setDescriptor] = useState('')
  const [report, setReport] = useState(null)
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
      setReport(cachedReport)
      setOffset(nextOffset)

      const hasIssues =
        (cachedReport?.findings?.length || 0) > 0 ||
        (cachedReport?.warnings?.length || 0) > 0

      setSuccess(hasIssues ? '' : 'Wallet analysis completed successfully.')
      setScreen('report')
      return
    }

    setScreen('loading')

    try {
      const result = await analyzeWallet(desc, nextOffset, SCAN_BATCH_SIZE)

      setReport(result)
      setOffset(nextOffset)
      setReportCache((prev) => ({
        ...prev,
        [cacheKey]: result,
      }))

      const hasIssues =
        (result?.findings?.length || 0) > 0 || (result?.warnings?.length || 0) > 0

      setSuccess(hasIssues ? '' : 'Wallet analysis completed successfully.')
      setScreen('report')
    } catch (err) {
      console.error('Analysis failed:', err)
      setReport(null)
      setSuccess('')
      setError(err.message || 'Analysis failed. Please try again.')
      setScreen('input')
    }
  }

  async function handleAnalyze(desc) {
    setReportCache({})
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
