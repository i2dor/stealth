const API_BASE = import.meta.env.VITE_API_BASE || ''

export const analyzeWallet = async (descriptor, offset = 0, count = 60, options = {}) => {
  const { branch = 'receive', auto = false } = options

  const params = new URLSearchParams({
    descriptor,
    offset: String(offset),
    count: String(count),
    branch,
    auto: auto ? '1' : '0',
  })

  const url = `${API_BASE}/api/scan?${params.toString()}`
  const res = await fetch(url)
  const text = await res.text()

  if (!res.ok) {
    let message = `Analysis failed (HTTP ${res.status})`
    try {
      const json = JSON.parse(text)
      if (json.error) message = json.error
    } catch (_) {}
    throw new Error(message)
  }

  try {
    return JSON.parse(text)
  } catch (err) {
    console.error('Invalid JSON from backend:', text)
    throw new Error('Invalid response from server.')
  }
}
