// SHA-512/224 and SHA-512/256 (FIPS 180-4). hash-wasm has no custom-IV SHA-512,
// so this is a small BigInt implementation — plenty fast for password-length input.
// Round constants and IVs are derived numerically (frac parts of prime roots and
// the SHA-512/t IV-generation function) rather than hardcoded tables.

const M64 = (1n << 64n) - 1n

function firstPrimes(n) {
  const out = []
  for (let c = 2; out.length < n; c++) {
    let prime = true
    for (let i = 0; out[i] * out[i] <= c; i++) {
      if (c % out[i] === 0) { prime = false; break }
    }
    if (prime) out.push(c)
  }
  return out
}

// floor(n^(1/k)) for BigInt n via Newton iteration
function iroot(n, k) {
  if (n < 2n) return n
  const K = BigInt(k)
  let x = 1n << BigInt(Math.ceil(n.toString(2).length / k) + 1)
  for (;;) {
    const y = ((K - 1n) * x + n / x ** (K - 1n)) / K
    if (y >= x) return x
    x = y
  }
}

// K[i] = first 64 bits of frac(cbrt(prime_i)); IV = first 64 bits of frac(sqrt(prime_i))
const K = firstPrimes(80).map((p) => iroot(BigInt(p) << 192n, 3) & M64)
const IV512 = firstPrimes(8).map((p) => iroot(BigInt(p) << 128n, 2) & M64)

const rotr = (x, r) => ((x >> BigInt(r)) | (x << BigInt(64 - r))) & M64

function compress(H, block) {
  const w = new Array(80)
  for (let i = 0; i < 16; i++) {
    let v = 0n
    for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(block[i * 8 + j])
    w[i] = v
  }
  for (let i = 16; i < 80; i++) {
    const s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7n)
    const s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6n)
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & M64
  }
  let [a, b, c, d, e, f, g, h] = H
  for (let i = 0; i < 80; i++) {
    const S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)
    const ch = (e & f) ^ (~e & M64 & g)
    const t1 = (h + S1 + ch + K[i] + w[i]) & M64
    const S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)
    const maj = (a & b) ^ (a & c) ^ (b & c)
    const t2 = (S0 + maj) & M64
    h = g; g = f; f = e
    e = (d + t1) & M64
    d = c; c = b; b = a
    a = (t1 + t2) & M64
  }
  H[0] = (H[0] + a) & M64; H[1] = (H[1] + b) & M64
  H[2] = (H[2] + c) & M64; H[3] = (H[3] + d) & M64
  H[4] = (H[4] + e) & M64; H[5] = (H[5] + f) & M64
  H[6] = (H[6] + g) & M64; H[7] = (H[7] + h) & M64
}

function sha512core(data, iv, outBytes) {
  const H = iv.slice()
  const bitLen = BigInt(data.length) * 8n
  const padded = new Uint8Array((Math.floor((data.length + 16) / 128) + 1) * 128)
  padded.set(data)
  padded[data.length] = 0x80
  for (let i = 0; i < 16; i++) {
    padded[padded.length - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xffn)
  }
  for (let off = 0; off < padded.length; off += 128) {
    compress(H, padded.subarray(off, off + 128))
  }
  const out = new Uint8Array(outBytes)
  for (let i = 0; i < outBytes; i++) {
    out[i] = Number((H[i >> 3] >> BigInt(8 * (7 - (i & 7)))) & 0xffn)
  }
  return out
}

// FIPS 180-4 §5.3.6: IV for SHA-512/t = SHA-512 of "SHA-512/t" using IV512 ^ a5a5...
const ivCache = {}
function ivFor(t) {
  if (!ivCache[t]) {
    const mod = IV512.map((v) => v ^ 0xa5a5a5a5a5a5a5a5n)
    const d = sha512core(new TextEncoder().encode(`SHA-512/${t}`), mod, 64)
    const iv = []
    for (let i = 0; i < 8; i++) {
      let v = 0n
      for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(d[i * 8 + j])
      iv.push(v)
    }
    ivCache[t] = iv
  }
  return ivCache[t]
}

export function sha512t(data, t /* 224 | 256 */) {
  return sha512core(data, ivFor(t), t / 8)
}
