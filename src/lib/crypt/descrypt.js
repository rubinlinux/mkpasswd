// Traditional DES crypt(3) and BSDi extended DES crypt.
// Contracts (mirror PHP crypt() semantics, incl. salt quirks):
//   desCrypt(password: Uint8Array, salt: string /* >=2 chars, first 2 used */) -> string (13 chars)
//   extDesCrypt(password: Uint8Array, salt: string /* "_" + 4 rounds chars + 4 salt chars */) -> string
// Must match tests/crypt-vectors.json types "std_des" and "ext_des" exactly.
//
// Implemented as a straightforward bit-level DES (FIPS 46-3 tables) with the
// classic crypt() salt perturbation: salt bit i swaps E-expansion output bits
// i and i+24 (equivalent to crypt_freesec.c's saltbits XOR-swap of r48l/r48r).

const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

// FIPS 46-3 tables (1-based bit positions, MSB of block = bit 1)
const IP = [
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
const FP = [
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
const E = [
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
const P = [
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
const PC1 = [
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
const PC2 = [
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
const SBOX = [
  [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
  ],
  [
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
  ],
  [
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
  ],
  [
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
  ],
  [
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
  ],
  [
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
  ],
  [
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
  ],
  [
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
  ],
]

function asciiToBin(ch) {
  const i = ITOA64.indexOf(ch)
  return i < 0 ? 0 : i
}

// 16 subkeys (48-bit as bit arrays) from an 8-byte key
function keySchedule(keyBytes) {
  const key = new Array(64)
  for (let i = 0; i < 64; i++) key[i] = (keyBytes[i >> 3] >> (7 - (i & 7))) & 1
  let cd = new Array(56)
  for (let i = 0; i < 56; i++) cd[i] = key[PC1[i] - 1]
  const subkeys = []
  for (let r = 0; r < 16; r++) {
    const s = SHIFTS[r]
    const c = cd.slice(0, 28)
    const d = cd.slice(28)
    cd = c.slice(s).concat(c.slice(0, s), d.slice(s), d.slice(0, s))
    const k = new Array(48)
    for (let i = 0; i < 48; i++) k[i] = cd[PC2[i] - 1]
    subkeys.push(k)
  }
  return subkeys
}

// Run `count` chained DES encryptions of an 8-byte block, with the crypt()
// salt perturbation (salt bit i set -> swap E-output bits i and i+24).
function desCipher(blockBytes, subkeys, saltBits, count) {
  const bits = new Array(64)
  for (let i = 0; i < 64; i++) bits[i] = (blockBytes[i >> 3] >> (7 - (i & 7))) & 1
  let L = new Array(32)
  let R = new Array(32)
  for (let i = 0; i < 32; i++) {
    L[i] = bits[IP[i] - 1]
    R[i] = bits[IP[32 + i] - 1]
  }
  const e = new Array(48)
  const f = new Array(32)
  while (count-- > 0) {
    for (let r = 0; r < 16; r++) {
      const k = subkeys[r]
      for (let i = 0; i < 48; i++) e[i] = R[E[i] - 1]
      for (let i = 0; i < 24; i++) {
        if ((saltBits >> i) & 1) {
          const t = e[i]
          e[i] = e[i + 24]
          e[i + 24] = t
        }
      }
      for (let s = 0; s < 8; s++) {
        const o = s * 6
        const b0 = e[o] ^ k[o]
        const b1 = e[o + 1] ^ k[o + 1]
        const b2 = e[o + 2] ^ k[o + 2]
        const b3 = e[o + 3] ^ k[o + 3]
        const b4 = e[o + 4] ^ k[o + 4]
        const b5 = e[o + 5] ^ k[o + 5]
        const val = SBOX[s][(((b0 << 1) | b5) << 4) | (b1 << 3) | (b2 << 2) | (b3 << 1) | b4]
        f[s * 4] = (val >> 3) & 1
        f[s * 4 + 1] = (val >> 2) & 1
        f[s * 4 + 2] = (val >> 1) & 1
        f[s * 4 + 3] = val & 1
      }
      const newR = new Array(32)
      for (let i = 0; i < 32; i++) newR[i] = L[i] ^ f[P[i] - 1]
      L = R
      R = newR
    }
    // preoutput block is R16 L16
    const t = L
    L = R
    R = t
  }
  const pre = L.concat(R)
  const out = new Uint8Array(8)
  for (let i = 0; i < 64; i++) {
    if (pre[FP[i] - 1]) out[i >> 3] |= 0x80 >> (i & 7)
  }
  return out
}

// 64-bit result + 2 zero pad bits -> 11 chars, 6 bits each, MSB-first
function encode64(bytes8) {
  let out = ''
  for (let i = 0; i < 11; i++) {
    let c = 0
    for (let j = 0; j < 6; j++) {
      c <<= 1
      const bi = i * 6 + j
      if (bi < 64) c |= (bytes8[bi >> 3] >> (7 - (bi & 7))) & 1
    }
    out += ITOA64[c]
  }
  return out
}

export function desCrypt(password, salt) {
  const keyBytes = new Uint8Array(8)
  for (let i = 0; i < 8 && i < password.length; i++) keyBytes[i] = (password[i] << 1) & 0xff
  const subkeys = keySchedule(keyBytes)
  const saltVal = asciiToBin(salt[0]) | (asciiToBin(salt[1]) << 6)
  const result = desCipher(new Uint8Array(8), subkeys, saltVal, 25)
  return salt[0] + salt[1] + encode64(result)
}

export function extDesCrypt(password, salt) {
  // salt: "_" + 4 count chars + 4 salt chars (little-endian 6-bit groups)
  let count = 0
  let saltVal = 0
  for (let i = 1; i < 5; i++) count |= asciiToBin(salt[i]) << ((i - 1) * 6)
  for (let i = 5; i < 9; i++) saltVal |= asciiToBin(salt[i]) << ((i - 5) * 6)

  const keyBuf = new Uint8Array(8)
  let ki = 0
  for (let i = 0; i < 8; i++) {
    if (ki < password.length) keyBuf[i] = (password[ki++] << 1) & 0xff
  }
  let subkeys = keySchedule(keyBuf)
  while (ki < password.length) {
    // Encrypt the key with itself, then XOR in the next 8 password bytes.
    keyBuf.set(desCipher(keyBuf, subkeys, 0, 1))
    for (let i = 0; i < 8 && ki < password.length; i++) keyBuf[i] ^= (password[ki++] << 1) & 0xff
    subkeys = keySchedule(keyBuf)
  }
  const result = desCipher(new Uint8Array(8), subkeys, saltVal, count)
  return salt.slice(0, 9) + encode64(result)
}
