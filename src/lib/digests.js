// Canonical map of PHP hash() algorithm name -> async (Uint8Array) => lowercase hex.
// WASM-backed (hash-wasm) where available, hand-ported JS for the rest.
// Every entry is verified against PHP-generated vectors in tests/vectors.json.

import {
  adler32, crc32, md4, md5, sha1, sha224, sha256, sha384, sha512,
  sha3, ripemd160, whirlpool, xxhash32, xxhash64, xxhash3, xxhash128,
  createCRC32,
} from 'hash-wasm'

// PHP crc32c = CRC-32/Castagnoli (reflected poly 0x82F63B78).
let crc32cHasher = null
async function crc32c(d) {
  if (!crc32cHasher) crc32cHasher = await createCRC32(0x82f63b78)
  crc32cHasher.init()
  crc32cHasher.update(d)
  return crc32cHasher.digest()
}
import { crc32bzip2, fnv132, fnv1a32, fnv164, fnv1a64, joaat } from './algos/checksums.js'
import { murmur3a, murmur3c, murmur3f } from './algos/murmur3.js'
import { sha512t } from './algos/sha512t.js'
import { tiger } from './algos/tiger.js'
import { gost } from './algos/gost.js'
import { snefru256 } from './algos/snefru.js'
import { haval } from './algos/haval.js'
import { md2 } from './algos/md2.js'
import { ripemd } from './algos/ripemd.js'

export function toHex(u8) {
  let s = ''
  for (const b of u8) s += b.toString(16).padStart(2, '0')
  return s
}

export const digestHex = {
  adler32: (d) => adler32(d),
  crc32: async (d) => toHex(crc32bzip2(d)), // PHP crc32 = CRC-32/BZIP2
  crc32b: (d) => crc32(d), // PHP crc32b = common reflected CRC-32
  crc32c: (d) => crc32c(d),
  fnv132: async (d) => toHex(fnv132(d)),
  fnv1a32: async (d) => toHex(fnv1a32(d)),
  fnv164: async (d) => toHex(fnv164(d)),
  fnv1a64: async (d) => toHex(fnv1a64(d)),
  joaat: async (d) => toHex(joaat(d)),
  murmur3a: async (d) => toHex(murmur3a(d)),
  murmur3c: async (d) => toHex(murmur3c(d)),
  murmur3f: async (d) => toHex(murmur3f(d)),
  xxh32: (d) => xxhash32(d),
  xxh64: (d) => xxhash64(d),
  xxh3: (d) => xxhash3(d),
  xxh128: (d) => xxhash128(d),
  md2: async (d) => toHex(md2(d)),
  md4: (d) => md4(d),
  md5: (d) => md5(d),
  sha1: (d) => sha1(d),
  sha224: (d) => sha224(d),
  sha256: (d) => sha256(d),
  sha384: (d) => sha384(d),
  sha512: (d) => sha512(d),
  'sha512/224': async (d) => toHex(sha512t(d, 224)),
  'sha512/256': async (d) => toHex(sha512t(d, 256)),
  'sha3-224': (d) => sha3(d, 224),
  'sha3-256': (d) => sha3(d, 256),
  'sha3-384': (d) => sha3(d, 384),
  'sha3-512': (d) => sha3(d, 512),
  ripemd128: async (d) => toHex(ripemd(d, 128)),
  ripemd160: (d) => ripemd160(d),
  ripemd256: async (d) => toHex(ripemd(d, 256)),
  ripemd320: async (d) => toHex(ripemd(d, 320)),
  whirlpool: (d) => whirlpool(d),
  snefru: async (d) => toHex(snefru256(d)),
  snefru256: async (d) => toHex(snefru256(d)),
  gost: async (d) => toHex(gost(d, false)),
  'gost-crypto': async (d) => toHex(gost(d, true)),
}

for (const passes of [3, 4]) {
  for (const bits of [128, 160, 192]) {
    digestHex[`tiger${bits},${passes}`] = async (d) => toHex(tiger(d, bits, passes))
  }
}
for (const passes of [3, 4, 5]) {
  for (const bits of [128, 160, 192, 224, 256]) {
    digestHex[`haval${bits},${passes}`] = async (d) => toHex(haval(d, passes, bits))
  }
}
