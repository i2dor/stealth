import { useState } from 'react'
import InputScreen from './screens/InputScreen'
import LoadingScreen from './screens/LoadingScreen'
import ReportScreen from './screens/ReportScreen'
import { analyzeWallet } from './services/walletService'

export default function App() {
  const [screen, setScreen] = useState('input')
  const [descriptor, setDescriptor] = useState('')
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  async function handleAnalyze(desc) {
    setDescriptor(desc)
    setError('')
    setSuccess('')
    setScreen('loading')

    try {
  const result = await analyzeWallet(desc)
  setReport(result)

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

  function handleReset() {
    setScreen('input')
    setDescriptor('')
    setReport(null)
    setError('')
    setSuccess('')
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
