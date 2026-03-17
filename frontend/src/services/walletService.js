export const analyzeWallet = async (descriptor) => {
  const res = await fetch(`/api/wallet/scan?descriptor=${encodeURIComponent(descriptor)}`)
  const text = await res.text()

  console.log('raw response text:', text)

  if (!res.ok) {
    throw new Error(`Analysis failed: ${text}`)
  }

  try {
    return JSON.parse(text)
  } catch (err) {
    console.error('Invalid JSON from backend:', text)
    throw err
  }
}
