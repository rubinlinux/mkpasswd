// Non-cryptographic checksums matching PHP hash() output byte order.
// All functions take a Uint8Array and return a big-endian Uint8Array.

export function be32(v) {
  return new Uint8Array([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255])
}

export function be64(v) {
  const b = new Uint8Array(8)
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return b
}

// PHP "crc32" is CRC-32/BZIP2: poly 0x04C11DB7 MSB-first, init/xorout 0xFFFFFFFF.
// (PHP "crc32b" is the common reflected variant, covered by hash-wasm.)
let bzTable = null
export function crc32bzip2(data) {
  if (!bzTable) {
    bzTable = new Uint32Array(256)
    for (let i = 0; i < 256; i++) {
      let r = i << 24
      for (let j = 0; j < 8; j++) {
        r = r & 0x80000000 ? ((r << 1) ^ 0x04c11db7) >>> 0 : (r << 1) >>> 0
      }
      bzTable[i] = r
    }
  }
  let c = 0xffffffff
  for (const b of data) {
    c = (((c << 8) >>> 0) ^ bzTable[((c >>> 24) ^ b) & 0xff]) >>> 0
  }
  // PHP's hash('crc32') emits the CRC-32/BZIP2 value in little-endian byte order.
  return be32((c ^ 0xffffffff) >>> 0).reverse()
}

const FNV32_PRIME = 0x01000193
const FNV32_INIT = 0x811c9dc5
const FNV64_PRIME = 0x100000001b3n
const FNV64_INIT = 0xcbf29ce484222325n
const M64 = (1n << 64n) - 1n

export function fnv132(data) {
  let h = FNV32_INIT
  for (const b of data) h = (Math.imul(h, FNV32_PRIME) >>> 0) ^ b
  return be32(h >>> 0)
}

export function fnv1a32(data) {
  let h = FNV32_INIT
  for (const b of data) h = Math.imul(h ^ b, FNV32_PRIME) >>> 0
  return be32(h >>> 0)
}

export function fnv164(data) {
  let h = FNV64_INIT
  for (const b of data) h = ((h * FNV64_PRIME) & M64) ^ BigInt(b)
  return be64(h)
}

export function fnv1a64(data) {
  let h = FNV64_INIT
  for (const b of data) h = ((h ^ BigInt(b)) * FNV64_PRIME) & M64
  return be64(h)
}

// Jenkins one-at-a-time
export function joaat(data) {
  let h = 0
  for (const b of data) {
    h = (h + b) >>> 0
    h = (h + ((h << 10) >>> 0)) >>> 0
    h = (h ^ (h >>> 6)) >>> 0
  }
  h = (h + ((h << 3) >>> 0)) >>> 0
  h = (h ^ (h >>> 11)) >>> 0
  h = (h + ((h << 15) >>> 0)) >>> 0
  return be32(h)
}
