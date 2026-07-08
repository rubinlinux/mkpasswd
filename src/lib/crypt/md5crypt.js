// MD5-crypt ($1$) and Apache APR1 ($apr1$).
// Contract (mirrors PHP crypt() semantics — pass the full salt spec):
//   md5Crypt(password: Uint8Array, saltSpec: string /* "$1$salt$..." or "$apr1$salt$..." */) -> string
// Salt parsing rules: magic is "$1$" or "$apr1$", salt is up to 8 chars, terminated by "$" or end.
// Must match tests/crypt-vectors.json types "md5" and "apr1" exactly.
// Poul-Henning Kamp's algorithm, transcribed from PHP's crypt_md5.c.
// Uses a local synchronous MD5 (hash-wasm is async, which would poison this
// whole call chain; a local sync MD5 keeps crypt sync).

// --- sync MD5 primitive ------------------------------------------------------

// K[i] = floor(abs(sin(i+1)) * 2^32); safe to derive in doubles — the nearest
// integer is never closer than ~0.015 while double error here is < 1e-6.
const K = new Array(64)
for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)
const S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]

function md5(data) {
  const bitLen = data.length * 8
  const padded = new Uint8Array((((data.length + 8) >> 6) + 1) * 64)
  padded.set(data)
  padded[data.length] = 0x80
  // 64-bit little-endian length (lengths here are far below 2^32 bits)
  padded[padded.length - 8] = bitLen & 0xff
  padded[padded.length - 7] = (bitLen >>> 8) & 0xff
  padded[padded.length - 6] = (bitLen >>> 16) & 0xff
  padded[padded.length - 5] = (bitLen >>> 24) & 0xff

  let h0 = 0x67452301
  let h1 = 0xefcdab89
  let h2 = 0x98badcfe
  let h3 = 0x10325476
  const m = new Array(16)
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      const o = off + i * 4
      m[i] = padded[o] | (padded[o + 1] << 8) | (padded[o + 2] << 16) | (padded[o + 3] << 24)
    }
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    for (let i = 0; i < 64; i++) {
      let f
      let g
      if (i < 16) {
        f = (b & c) | (~b & d)
        g = i
      } else if (i < 32) {
        f = (d & b) | (~d & c)
        g = (5 * i + 1) & 15
      } else if (i < 48) {
        f = b ^ c ^ d
        g = (3 * i + 5) & 15
      } else {
        f = c ^ (b | ~d)
        g = (7 * i) & 15
      }
      const tmp = d
      d = c
      c = b
      const sum = (a + f + K[i] + m[g]) | 0
      const s = S[i]
      b = (b + ((sum << s) | (sum >>> (32 - s)))) | 0
      a = tmp
    }
    h0 = (h0 + a) | 0
    h1 = (h1 + b) | 0
    h2 = (h2 + c) | 0
    h3 = (h3 + d) | 0
  }
  const out = new Uint8Array(16)
  const hs = [h0, h1, h2, h3]
  for (let i = 0; i < 16; i++) out[i] = (hs[i >> 2] >>> ((i & 3) * 8)) & 0xff
  return out
}

// --- md5-crypt ---------------------------------------------------------------

const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

function to64(v, n) {
  let out = ''
  while (n-- > 0) {
    out += ITOA64[v & 0x3f]
    v >>>= 6
  }
  return out
}

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

export function md5Crypt(password, saltSpec) {
  let magic = '$1$'
  let sp = saltSpec
  if (sp.startsWith('$apr1$')) {
    magic = '$apr1$'
    sp = sp.slice(6)
  } else if (sp.startsWith('$1$')) {
    sp = sp.slice(3)
  }
  // Salt stops at the first '$', max 8 chars
  let end = sp.indexOf('$')
  if (end < 0 || end > 8) end = Math.min(sp.length, 8)
  const saltStr = sp.slice(0, end)
  const salt = ascii(saltStr)
  const magicBytes = ascii(magic)
  const pw = password
  const pl = pw.length

  // ctx: pw, magic, salt
  const ctxParts = [pw, magicBytes, salt]
  // ctx1 = MD5(pw salt pw)
  let final = md5(concatBytes([pw, salt, pw]))
  for (let i = pl; i > 0; i -= 16) ctxParts.push(final.subarray(0, Math.min(i, 16)))
  // the characteristic length-dependent bit trickle (final is zeroed first)
  const zero = new Uint8Array(1)
  const pw0 = pw.subarray(0, 1) // first byte of pw (empty if pw is empty)
  for (let i = pl; i > 0; i >>= 1) ctxParts.push(i & 1 ? zero : pw0)
  final = md5(concatBytes(ctxParts))

  // 1000 rounds of alternating pw/salt/magic-free mixing
  for (let i = 0; i < 1000; i++) {
    const parts = []
    parts.push(i & 1 ? pw : final)
    if (i % 3) parts.push(salt)
    if (i % 7) parts.push(pw)
    parts.push(i & 1 ? final : pw)
    final = md5(concatBytes(parts))
  }

  let hash = ''
  hash += to64((final[0] << 16) | (final[6] << 8) | final[12], 4)
  hash += to64((final[1] << 16) | (final[7] << 8) | final[13], 4)
  hash += to64((final[2] << 16) | (final[8] << 8) | final[14], 4)
  hash += to64((final[3] << 16) | (final[9] << 8) | final[15], 4)
  hash += to64((final[4] << 16) | (final[10] << 8) | final[5], 4)
  hash += to64(final[11], 2)

  return magic + saltStr + '$' + hash
}
