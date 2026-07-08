// MurmurHash3 variants matching PHP hash() naming and output byte order:
//   murmur3a = MurmurHash3_x86_32, murmur3c = MurmurHash3_x86_128,
//   murmur3f = MurmurHash3_x64_128. Seed 0 (PHP default).
// All take a Uint8Array, return a big-endian Uint8Array (PHP prints words BE).

import { be32, be64 } from './checksums.js'

const rotl32 = (x, r) => ((x << r) | (x >>> (32 - r))) >>> 0

function fmix32(h) {
  h ^= h >>> 16
  h = Math.imul(h, 0x85ebca6b) >>> 0
  h ^= h >>> 13
  h = Math.imul(h, 0xc2b2ae35) >>> 0
  h ^= h >>> 16
  return h >>> 0
}

export function murmur3a(data, seed = 0) {
  const c1 = 0xcc9e2d51
  const c2 = 0x1b873593
  let h = seed >>> 0
  const n = data.length & ~3
  for (let i = 0; i < n; i += 4) {
    let k = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
    k = Math.imul(k, c1)
    k = rotl32(k, 15)
    k = Math.imul(k, c2)
    h = (h ^ k) >>> 0
    h = rotl32(h, 13)
    h = (Math.imul(h, 5) + 0xe6546b64) >>> 0
  }
  let k = 0
  switch (data.length & 3) {
    case 3: k ^= data[n + 2] << 16 // fallthrough
    case 2: k ^= data[n + 1] << 8 // fallthrough
    case 1:
      k ^= data[n]
      k = Math.imul(k, c1)
      k = rotl32(k, 15)
      k = Math.imul(k, c2)
      h = (h ^ k) >>> 0
  }
  h = (h ^ data.length) >>> 0
  return be32(fmix32(h))
}

export function murmur3c(data, seed = 0) {
  const c1 = 0x239b961b, c2 = 0xab0e9789, c3 = 0x38b34ae5, c4 = 0xa1e38b93
  let h1 = seed >>> 0, h2 = seed >>> 0, h3 = seed >>> 0, h4 = seed >>> 0
  const len = data.length
  const n = len & ~15
  const w = (i) => (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)) >>> 0
  for (let i = 0; i < n; i += 16) {
    let k1 = w(i), k2 = w(i + 4), k3 = w(i + 8), k4 = w(i + 12)
    k1 = Math.imul(k1, c1); k1 = rotl32(k1, 15); k1 = Math.imul(k1, c2); h1 = (h1 ^ k1) >>> 0
    h1 = rotl32(h1, 19); h1 = (h1 + h2) >>> 0; h1 = (Math.imul(h1, 5) + 0x561ccd1b) >>> 0
    k2 = Math.imul(k2, c2); k2 = rotl32(k2, 16); k2 = Math.imul(k2, c3); h2 = (h2 ^ k2) >>> 0
    h2 = rotl32(h2, 17); h2 = (h2 + h3) >>> 0; h2 = (Math.imul(h2, 5) + 0x0bcaa747) >>> 0
    k3 = Math.imul(k3, c3); k3 = rotl32(k3, 17); k3 = Math.imul(k3, c4); h3 = (h3 ^ k3) >>> 0
    h3 = rotl32(h3, 15); h3 = (h3 + h4) >>> 0; h3 = (Math.imul(h3, 5) + 0x96cd1c35) >>> 0
    k4 = Math.imul(k4, c4); k4 = rotl32(k4, 18); k4 = Math.imul(k4, c1); h4 = (h4 ^ k4) >>> 0
    h4 = rotl32(h4, 13); h4 = (h4 + h1) >>> 0; h4 = (Math.imul(h4, 5) + 0x32ac3b17) >>> 0
  }
  let k1 = 0, k2 = 0, k3 = 0, k4 = 0
  const t = data.subarray(n)
  switch (len & 15) {
    case 15: k4 ^= t[14] << 16 // fallthrough
    case 14: k4 ^= t[13] << 8 // fallthrough
    case 13:
      k4 ^= t[12]
      k4 = Math.imul(k4, c4); k4 = rotl32(k4, 18); k4 = Math.imul(k4, c1); h4 = (h4 ^ k4) >>> 0
    // fallthrough
    case 12: k3 ^= t[11] << 24 // fallthrough
    case 11: k3 ^= t[10] << 16 // fallthrough
    case 10: k3 ^= t[9] << 8 // fallthrough
    case 9:
      k3 ^= t[8]
      k3 = Math.imul(k3, c3); k3 = rotl32(k3, 17); k3 = Math.imul(k3, c4); h3 = (h3 ^ k3) >>> 0
    // fallthrough
    case 8: k2 ^= t[7] << 24 // fallthrough
    case 7: k2 ^= t[6] << 16 // fallthrough
    case 6: k2 ^= t[5] << 8 // fallthrough
    case 5:
      k2 ^= t[4]
      k2 = Math.imul(k2, c2); k2 = rotl32(k2, 16); k2 = Math.imul(k2, c3); h2 = (h2 ^ k2) >>> 0
    // fallthrough
    case 4: k1 ^= t[3] << 24 // fallthrough
    case 3: k1 ^= t[2] << 16 // fallthrough
    case 2: k1 ^= t[1] << 8 // fallthrough
    case 1:
      k1 ^= t[0]
      k1 = Math.imul(k1, c1); k1 = rotl32(k1, 15); k1 = Math.imul(k1, c2); h1 = (h1 ^ k1) >>> 0
  }
  h1 = (h1 ^ len) >>> 0; h2 = (h2 ^ len) >>> 0; h3 = (h3 ^ len) >>> 0; h4 = (h4 ^ len) >>> 0
  h1 = (h1 + h2) >>> 0; h1 = (h1 + h3) >>> 0; h1 = (h1 + h4) >>> 0
  h2 = (h2 + h1) >>> 0; h3 = (h3 + h1) >>> 0; h4 = (h4 + h1) >>> 0
  h1 = fmix32(h1); h2 = fmix32(h2); h3 = fmix32(h3); h4 = fmix32(h4)
  h1 = (h1 + h2) >>> 0; h1 = (h1 + h3) >>> 0; h1 = (h1 + h4) >>> 0
  h2 = (h2 + h1) >>> 0; h3 = (h3 + h1) >>> 0; h4 = (h4 + h1) >>> 0
  const out = new Uint8Array(16)
  out.set(be32(h1), 0); out.set(be32(h2), 4); out.set(be32(h3), 8); out.set(be32(h4), 12)
  return out
}

const M64 = (1n << 64n) - 1n
const rotl64 = (x, r) => ((x << BigInt(r)) | (x >> BigInt(64 - r))) & M64

function fmix64(k) {
  k ^= k >> 33n
  k = (k * 0xff51afd7ed558ccdn) & M64
  k ^= k >> 33n
  k = (k * 0xc4ceb9fe1a85ec53n) & M64
  k ^= k >> 33n
  return k
}

export function murmur3f(data, seed = 0) {
  const c1 = 0x87c37b91114253d5n
  const c2 = 0x4cf5ad432745937fn
  let h1 = BigInt(seed >>> 0), h2 = BigInt(seed >>> 0)
  const len = data.length
  const n = len & ~15
  const w64 = (i) => {
    let v = 0n
    for (let j = 7; j >= 0; j--) v = (v << 8n) | BigInt(data[i + j])
    return v
  }
  for (let i = 0; i < n; i += 16) {
    let k1 = w64(i), k2 = w64(i + 8)
    k1 = (k1 * c1) & M64; k1 = rotl64(k1, 31); k1 = (k1 * c2) & M64; h1 ^= k1
    h1 = rotl64(h1, 27); h1 = (h1 + h2) & M64; h1 = (h1 * 5n + 0x52dce729n) & M64
    k2 = (k2 * c2) & M64; k2 = rotl64(k2, 33); k2 = (k2 * c1) & M64; h2 ^= k2
    h2 = rotl64(h2, 31); h2 = (h2 + h1) & M64; h2 = (h2 * 5n + 0x38495ab5n) & M64
  }
  let k1 = 0n, k2 = 0n
  const t = data.subarray(n)
  const B = (i) => BigInt(t[i])
  switch (len & 15) {
    case 15: k2 ^= B(14) << 48n // fallthrough
    case 14: k2 ^= B(13) << 40n // fallthrough
    case 13: k2 ^= B(12) << 32n // fallthrough
    case 12: k2 ^= B(11) << 24n // fallthrough
    case 11: k2 ^= B(10) << 16n // fallthrough
    case 10: k2 ^= B(9) << 8n // fallthrough
    case 9:
      k2 ^= B(8)
      k2 = (k2 * c2) & M64; k2 = rotl64(k2, 33); k2 = (k2 * c1) & M64; h2 ^= k2
    // fallthrough
    case 8: k1 ^= B(7) << 56n // fallthrough
    case 7: k1 ^= B(6) << 48n // fallthrough
    case 6: k1 ^= B(5) << 40n // fallthrough
    case 5: k1 ^= B(4) << 32n // fallthrough
    case 4: k1 ^= B(3) << 24n // fallthrough
    case 3: k1 ^= B(2) << 16n // fallthrough
    case 2: k1 ^= B(1) << 8n // fallthrough
    case 1:
      k1 ^= B(0)
      k1 = (k1 * c1) & M64; k1 = rotl64(k1, 31); k1 = (k1 * c2) & M64; h1 ^= k1
  }
  h1 ^= BigInt(len); h2 ^= BigInt(len)
  h1 = (h1 + h2) & M64
  h2 = (h2 + h1) & M64
  h1 = fmix64(h1)
  h2 = fmix64(h2)
  h1 = (h1 + h2) & M64
  h2 = (h2 + h1) & M64
  const out = new Uint8Array(16)
  out.set(be64(h1), 0)
  out.set(be64(h2), 8)
  return out
}
