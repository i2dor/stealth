const API_BASE =
  import.meta.env.VITE_API_BASE || 'https://stealth-backend-lv38.onrender.com'

export const analyzeWallet = async (descriptor, offset = 0, count = 100) => {
  const params = new URLSearchParams({
    descriptor,
    offset: String(offset),
    count: String(count),
  })

  const url = `${API_BASE}/api/wallet/scan?${params.toString()}`
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
