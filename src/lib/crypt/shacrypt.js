// SHA-256 crypt ($5$) and SHA-512 crypt ($6$) — Ulrich Drepper's algorithm (glibc),
// transcribed from PHP's crypt_sha256.c / crypt_sha512.c.
// Contract (mirrors PHP crypt() semantics — pass the full salt spec):
//   sha256Crypt(password: Uint8Array, saltSpec: string /* "$5$[rounds=N$]salt$..." */) -> string
//   sha512Crypt(password: Uint8Array, saltSpec: string /* "$6$[rounds=N$]salt$..." */) -> string
// rounds= is clamped to 1000..999999999 (default 5000) and echoed in the output
// only when explicitly present in the input. Salt max 16 chars, stops at '$'.
// Sync SHA-256 (32-bit) and SHA-512 (BigInt, same core as ../algos/sha512t.js)
// primitives are implemented locally so crypt stays synchronous.

// --- shared constant derivation (K = frac(cbrt(prime)), IV = frac(sqrt(prime))) --

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

// --- sync SHA-256 ------------------------------------------------------------

const K256 = firstPrimes(64).map((p) => Number(iroot(BigInt(p) << 96n, 3) & 0xffffffffn))
const IV256 = firstPrimes(8).map((p) => Number(iroot(BigInt(p) << 64n, 2) & 0xffffffffn))

function sha256(data) {
  const H = IV256.slice()
  const bitLen = data.length * 8
  const padded = new Uint8Array((((data.length + 8) >> 6) + 1) * 64)
  padded.set(data)
  padded[data.length] = 0x80
  padded[padded.length - 4] = (bitLen >>> 24) & 0xff
  padded[padded.length - 3] = (bitLen >>> 16) & 0xff
  padded[padded.length - 2] = (bitLen >>> 8) & 0xff
  padded[padded.length - 1] = bitLen & 0xff

  const w = new Array(64)
  const rotr = (x, r) => ((x >>> r) | (x << (32 - r))) >>> 0
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      const o = off + i * 4
      w[i] = ((padded[o] << 24) | (padded[o + 1] << 16) | (padded[o + 2] << 8) | padded[o + 3]) >>> 0
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0
    }
    let [a, b, c, d, e, f, g, h] = H
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const ch = (e & f) ^ (~e & g)
      const t1 = (h + S1 + ch + K256[i] + w[i]) | 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + maj) | 0
      h = g; g = f; f = e
      e = (d + t1) | 0
      d = c; c = b; b = a
      a = (t1 + t2) | 0
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0
    H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0
    H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0
  }
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) out[i] = (H[i >> 2] >>> (8 * (3 - (i & 3)))) & 0xff
  return out
}

// --- sync SHA-512 (BigInt core, as in ../algos/sha512t.js) --------------------

const M64 = (1n << 64n) - 1n
const K512 = firstPrimes(80).map((p) => iroot(BigInt(p) << 192n, 3) & M64)
const IV512 = firstPrimes(8).map((p) => iroot(BigInt(p) << 128n, 2) & M64)
const rotr64 = (x, r) => ((x >> BigInt(r)) | (x << BigInt(64 - r))) & M64

function compress512(H, block) {
  const w = new Array(80)
  for (let i = 0; i < 16; i++) {
    let v = 0n
    for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(block[i * 8 + j])
    w[i] = v
  }
  for (let i = 16; i < 80; i++) {
    const s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7n)
    const s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6n)
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & M64
  }
  let [a, b, c, d, e, f, g, h] = H
  for (let i = 0; i < 80; i++) {
    const S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
    const ch = (e & f) ^ (~e & M64 & g)
    const t1 = (h + S1 + ch + K512[i] + w[i]) & M64
    const S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
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

function sha512(data) {
  const H = IV512.slice()
  const bitLen = BigInt(data.length) * 8n
  const padded = new Uint8Array((Math.floor((data.length + 16) / 128) + 1) * 128)
  padded.set(data)
  padded[data.length] = 0x80
  for (let i = 0; i < 16; i++) {
    padded[padded.length - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xffn)
  }
  for (let off = 0; off < padded.length; off += 128) {
    compress512(H, padded.subarray(off, off + 128))
  }
  const out = new Uint8Array(64)
  for (let i = 0; i < 64; i++) {
    out[i] = Number((H[i >> 3] >> BigInt(8 * (7 - (i & 7)))) & 0xffn)
  }
  return out
}

// --- sha-crypt ---------------------------------------------------------------

const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
const ROUNDS_DEFAULT = 5000
const ROUNDS_MIN = 1000
const ROUNDS_MAX = 999999999
const SALT_LEN_MAX = 16

function concatBytes(parts) {
  let len = 0
  for (const p of parts) len += p.length
  const out = new Uint8Array(len)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0))

// glibc output byte permutation: triples (b2, b1, b0) into b64_from_24bit.
// For digest length D with cycle c = D - (D >> 5) ... the concrete patterns:
//   sha256: k=0..9  -> ((21k)%30, (10+21k)%30, (20+21k)%30) x4 chars, then (-, 31, 30) x3
//   sha512: k=0..20 -> ((22k)%63, (21+22k)%63, (42+22k)%63) x4 chars, then (-, -, 63) x2
function perm256() {
  const out = []
  for (let k = 0; k < 10; k++) out.push([(21 * k) % 30, (10 + 21 * k) % 30, (20 + 21 * k) % 30, 4])
  out.push([-1, 31, 30, 3])
  return out
}
function perm512() {
  const out = []
  for (let k = 0; k < 21; k++) out.push([(22 * k) % 63, (21 + 22 * k) % 63, (42 + 22 * k) % 63, 4])
  out.push([-1, -1, 63, 2])
  return out
}

function shaCrypt(password, saltSpec, prefix, H, dlen, perm) {
  let sp = saltSpec
  if (sp.startsWith(prefix)) sp = sp.slice(prefix.length)
  let rounds = ROUNDS_DEFAULT
  let roundsCustom = false
  const m = sp.match(/^rounds=(\d+)\$/)
  if (m) {
    sp = sp.slice(m[0].length)
    rounds = Math.max(ROUNDS_MIN, Math.min(parseInt(m[1], 10), ROUNDS_MAX))
    roundsCustom = true
  }
  let end = sp.indexOf('$')
  if (end < 0) end = sp.length
  const saltStr = sp.slice(0, Math.min(end, SALT_LEN_MAX))
  const salt = ascii(saltStr)
  const pw = password
  const keyLen = pw.length
  const saltLen = salt.length

  // digest B = H(pw salt pw)
  const B = H(concatBytes([pw, salt, pw]))

  // digest A = H(pw, salt, B repeated/truncated to keyLen, bit-trickle)
  const aParts = [pw, salt]
  let cnt
  for (cnt = keyLen; cnt > dlen; cnt -= dlen) aParts.push(B)
  aParts.push(B.subarray(0, cnt))
  for (cnt = keyLen; cnt > 0; cnt >>= 1) aParts.push(cnt & 1 ? B : pw)
  let A = H(concatBytes(aParts))

  // P sequence: H(pw repeated keyLen times), repeated/truncated to keyLen bytes
  const pParts = []
  for (cnt = 0; cnt < keyLen; cnt++) pParts.push(pw)
  const DP = H(concatBytes(pParts))
  const p = new Uint8Array(keyLen)
  for (let o = 0; o < keyLen; o += dlen) p.set(DP.subarray(0, Math.min(dlen, keyLen - o)), o)

  // S sequence: H(salt repeated 16+A[0] times), repeated/truncated to saltLen bytes
  const sParts = []
  for (cnt = 0; cnt < 16 + A[0]; cnt++) sParts.push(salt)
  const DS = H(concatBytes(sParts))
  const s = new Uint8Array(saltLen)
  for (let o = 0; o < saltLen; o += dlen) s.set(DS.subarray(0, Math.min(dlen, saltLen - o)), o)

  // the rounds of mixing
  for (let i = 0; i < rounds; i++) {
    const parts = []
    parts.push(i & 1 ? p : A)
    if (i % 3) parts.push(s)
    if (i % 7) parts.push(p)
    parts.push(i & 1 ? A : p)
    A = H(concatBytes(parts))
  }

  let out = prefix
  if (roundsCustom) out += `rounds=${rounds}$`
  out += saltStr + '$'
  for (const [i2, i1, i0, n] of perm) {
    let w = ((i2 < 0 ? 0 : A[i2]) << 16) | ((i1 < 0 ? 0 : A[i1]) << 8) | A[i0]
    for (let j = 0; j < n; j++) {
      out += ITOA64[w & 0x3f]
      w >>>= 6
    }
  }
  return out
}

const PERM256 = perm256()
const PERM512 = perm512()

export function sha256Crypt(password, saltSpec) {
  return shaCrypt(password, saltSpec, '$5$', sha256, 32, PERM256)
}

export function sha512Crypt(password, saltSpec) {
  return shaCrypt(password, saltSpec, '$6$', sha512, 64, PERM512)
}
