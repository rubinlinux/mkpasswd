// Base64 helpers that work on raw bytes (independent of btoa/atob edge cases).

const STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

export function bytesToB64(bytes, { pad = true } = {}) {
  let out = ''
  let i = 0
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]
    out += STD[(n >> 18) & 63] + STD[(n >> 12) & 63] + STD[(n >> 6) & 63] + STD[n & 63]
  }
  const rem = bytes.length - i
  if (rem === 1) {
    const n = bytes[i] << 16
    out += STD[(n >> 18) & 63] + STD[(n >> 12) & 63]
    if (pad) out += '=='
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8)
    out += STD[(n >> 18) & 63] + STD[(n >> 12) & 63] + STD[(n >> 6) & 63]
    if (pad) out += '='
  }
  return out
}

export function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2)
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return b
}

export function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) { out.set(p, off); off += p.length }
  return out
}
