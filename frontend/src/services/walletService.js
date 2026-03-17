const API_BASE =
  import.meta.env.VITE_API_BASE || 'https://stealth-backend-lv38.onrender.com'

export const analyzeWallet = async (descriptor) => {
  const url = `${API_BASE}/api/wallet/scan?descriptor=${encodeURIComponent(descriptor)}`
  const res = await fetch(url)
  const text = await res.text()

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
