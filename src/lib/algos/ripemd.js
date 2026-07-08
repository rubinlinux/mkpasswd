// RIPEMD-128/160/256/320. (The app uses hash-wasm for 160; implementing all four
// here is fine since 128/256 and 160/320 share cores.)
// Contract: ripemd(data: Uint8Array, widthBits: 128|160|256|320) -> Uint8Array
// Must match PHP hash() output exactly (see tests/vectors.json).
// Transcribed from php-src ext/hash/hash_ripemd.c.

// prettier-ignore
const R = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
// prettier-ignore
const RR = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
// prettier-ignore
const SH = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
// prettier-ignore
const SHH = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]

const K = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]
const KK4 = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x00000000]
const KK5 = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000]

// Which register (0=a,1=b,2=c,3=d,4=e) the two lines exchange after each round.
const SWAP256 = [0, 1, 2, 3]
const SWAP320 = [1, 3, 0, 2, 4]

const rol = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0

function F(q, x, y, z) {
  switch (q) {
    case 0: return (x ^ y ^ z) >>> 0
    case 1: return ((x & y) | (~x & z)) >>> 0
    case 2: return ((x | ~y) ^ z) >>> 0
    case 3: return ((x & z) | (y & ~z)) >>> 0
    default: return (x ^ (y | ~z)) >>> 0
  }
}

function transform(widthBits, h, x) {
  const five = widthBits === 160 || widthBits === 320
  const dual = widthBits === 256 || widthBits === 320
  const rounds = five ? 5 : 4
  const KKt = five ? KK5 : KK4
  const half = five ? 5 : 4

  // Left line registers; right line uses the same start values for 128/160,
  // the second half of the state for 256/320.
  const L = [h[0], h[1], h[2], h[3], five ? h[4] : 0]
  const RG = dual
    ? [h[half], h[half + 1], h[half + 2], h[half + 3], five ? h[half + 4] : 0]
    : L.slice()

  for (let q = 0; q < rounds; q++) {
    const k = K[q]
    const kk = KKt[q]
    const fq = q
    const fqq = rounds - 1 - q
    for (let j = q * 16; j < q * 16 + 16; j++) {
      let t = rol((L[0] + F(fq, L[1], L[2], L[3]) + x[R[j]] + k) >>> 0, SH[j])
      if (five) {
        t = (t + L[4]) >>> 0
        L[0] = L[4]; L[4] = L[3]; L[3] = rol(L[2], 10)
      } else {
        L[0] = L[3]; L[3] = L[2]
      }
      L[2] = L[1]; L[1] = t

      let tt = rol((RG[0] + F(fqq, RG[1], RG[2], RG[3]) + x[RR[j]] + kk) >>> 0, SHH[j])
      if (five) {
        tt = (tt + RG[4]) >>> 0
        RG[0] = RG[4]; RG[4] = RG[3]; RG[3] = rol(RG[2], 10)
      } else {
        RG[0] = RG[3]; RG[3] = RG[2]
      }
      RG[2] = RG[1]; RG[1] = tt
    }
    if (dual) {
      const i = (five ? SWAP320 : SWAP256)[q]
      const tmp = L[i]; L[i] = RG[i]; RG[i] = tmp
    }
  }

  if (widthBits === 128) {
    const tmp = (h[1] + L[2] + RG[3]) >>> 0
    h[1] = (h[2] + L[3] + RG[0]) >>> 0
    h[2] = (h[3] + L[0] + RG[1]) >>> 0
    h[3] = (h[0] + L[1] + RG[2]) >>> 0
    h[0] = tmp
  } else if (widthBits === 160) {
    const tmp = (h[1] + L[2] + RG[3]) >>> 0
    h[1] = (h[2] + L[3] + RG[4]) >>> 0
    h[2] = (h[3] + L[4] + RG[0]) >>> 0
    h[3] = (h[4] + L[0] + RG[1]) >>> 0
    h[4] = (h[0] + L[1] + RG[2]) >>> 0
    h[0] = tmp
  } else {
    for (let i = 0; i < half; i++) {
      h[i] = (h[i] + L[i]) >>> 0
      h[half + i] = (h[half + i] + RG[i]) >>> 0
    }
  }
}

const IV = {
  128: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
  160: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
  256: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
        0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567],
  320: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
        0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567, 0x3c2d1e0f],
}

export function ripemd(data, widthBits) {
  const iv = IV[widthBits]
  if (!iv) throw new Error(`ripemd: unsupported width ${widthBits}`)
  const h = Uint32Array.from(iv)

  // MD-style padding: 0x80, zeros, 64-bit little-endian bit length.
  const bitLenLo = (data.length << 3) >>> 0
  const bitLenHi = Math.floor(data.length / 0x20000000)
  const padded = new Uint8Array((Math.floor((data.length + 8) / 64) + 1) * 64)
  padded.set(data, 0)
  padded[data.length] = 0x80
  const dv = new DataView(padded.buffer)
  dv.setUint32(padded.length - 8, bitLenLo, true)
  dv.setUint32(padded.length - 4, bitLenHi, true)

  const x = new Uint32Array(16)
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) x[i] = dv.getUint32(off + i * 4, true)
    transform(widthBits, h, x)
  }

  const out = new Uint8Array(widthBits / 8)
  const ov = new DataView(out.buffer)
  for (let i = 0; i < h.length; i++) ov.setUint32(i * 4, h[i], true)
  return out
}
