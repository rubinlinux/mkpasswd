// HAVAL (PHP "haval128,3" ... "haval256,5" — 15 variants).
// Contract: haval(data: Uint8Array, passes: 3|4|5, widthBits: 128|160|192|224|256) -> Uint8Array
// Must match PHP hash() output exactly (see tests/vectors.json).
// Transcribed from php-src ext/hash/hash_haval.c.

const D0 = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
]

// prettier-ignore
const K2 = [
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
  0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
  0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
  0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5,
]
// prettier-ignore
const K3 = [
  0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
  0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94,
  0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993,
  0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
]
// prettier-ignore
const K4 = [
  0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991,
  0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
  0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
  0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4,
]
// prettier-ignore
const K5 = [
  0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4,
  0x7d84a5c3, 0x3b8b5ebe, 0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706,
  0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b,
  0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4,
]

// prettier-ignore
const I2 = [
  5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8,
  30, 3, 21, 9, 17, 24, 29, 6, 19, 12, 15, 13, 2, 25, 31, 27,
]
// prettier-ignore
const I3 = [
  19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26,
  31, 15, 7, 3, 1, 0, 18, 27, 13, 6, 21, 10, 23, 11, 5, 2,
]
// prettier-ignore
const I4 = [
  24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3,
  22, 11, 31, 21, 8, 27, 12, 9, 1, 29, 5, 15, 17, 10, 16, 13,
]
// prettier-ignore
const I5 = [
  27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10,
  5, 9, 14, 30, 18, 6, 28, 24, 2, 23, 16, 22, 4, 1, 25, 15,
]

const PERMS = [null, I2, I3, I4, I5]
const CONSTS = [null, K2, K3, K4, K5]

// Boolean functions F1..F5, argument order (x6,x5,x4,x3,x2,x1,x0) as in PHP macros.
const F1 = (x6, x5, x4, x3, x2, x1, x0) =>
  (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1) ^ x0
const F2 = (x6, x5, x4, x3, x2, x1, x0) =>
  (x1 & x2 & x3) ^ (x2 & x4 & x5) ^ (x1 & x2) ^ (x1 & x4) ^
  (x2 & x6) ^ (x3 & x5) ^ (x4 & x5) ^ (x0 & x2) ^ x0
const F3 = (x6, x5, x4, x3, x2, x1, x0) =>
  (x1 & x2 & x3) ^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x3) ^ x0
const F4 = (x6, x5, x4, x3, x2, x1, x0) =>
  (x1 & x2 & x3) ^ (x2 & x4 & x5) ^ (x3 & x4 & x6) ^
  (x1 & x4) ^ (x2 & x6) ^ (x3 & x4) ^ (x3 & x5) ^
  (x3 & x6) ^ (x4 & x5) ^ (x4 & x6) ^ (x0 & x4) ^ x0
const F5 = (x6, x5, x4, x3, x2, x1, x0) =>
  (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1 & x2 & x3) ^ (x0 & x5) ^ x0

const FNS = [F1, F2, F3, F4, F5]

// Register-selection orders per (total passes, pass number): each entry lists
// the M-table selectors used as arguments (x6..x0) of the pass's F function.
const ORDERS = {
  3: [
    [1, 0, 3, 5, 6, 2, 4],
    [4, 2, 1, 0, 5, 3, 6],
    [6, 1, 2, 3, 4, 5, 0],
  ],
  4: [
    [2, 6, 1, 4, 5, 3, 0],
    [3, 5, 2, 0, 1, 6, 4],
    [1, 4, 3, 6, 0, 2, 5],
    [6, 4, 0, 5, 2, 1, 3],
  ],
  5: [
    [3, 4, 1, 0, 5, 2, 6],
    [6, 2, 1, 0, 3, 4, 5],
    [2, 6, 0, 4, 3, 1, 5],
    [1, 5, 3, 2, 0, 4, 6],
    [2, 5, 0, 6, 4, 3, 1],
  ],
}

const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0

function transform(passes, state, x) {
  const E = [
    state[0], state[1], state[2], state[3],
    state[4], state[5], state[6], state[7],
  ]
  const orders = ORDERS[passes]
  for (let p = 0; p < passes; p++) {
    const ord = orders[p]
    const fn = FNS[p]
    const perm = PERMS[p]
    const kc = CONSTS[p]
    for (let i = 0; i < 32; i++) {
      // M-table selector: Mk[i] = (k - i) mod 8
      const f = fn(
        E[(ord[0] - i) & 7], E[(ord[1] - i) & 7], E[(ord[2] - i) & 7],
        E[(ord[3] - i) & 7], E[(ord[4] - i) & 7], E[(ord[5] - i) & 7],
        E[(ord[6] - i) & 7],
      ) >>> 0
      E[(7 - i) & 7] =
        (rotr(f, 7) + rotr(E[(7 - i) & 7], 11) +
          (perm ? x[perm[i]] : x[i]) + (kc ? kc[i] : 0)) >>> 0
    }
  }
  for (let i = 0; i < 8; i++) state[i] = (state[i] + E[i]) >>> 0
}

// Tailoring (fold 256-bit state down to the requested width) — from
// PHP_HAVAL{128,160,192,224}Final.
function tailor(s, widthBits) {
  const s4 = s[4], s5 = s[5], s6 = s[6], s7 = s[7]
  if (widthBits === 128) {
    s[3] += (s7 & 0xff000000) | (s6 & 0x00ff0000) | (s5 & 0x0000ff00) | (s4 & 0x000000ff)
    s[2] += ((((s7 & 0x00ff0000) | (s6 & 0x0000ff00) | (s5 & 0x000000ff)) << 8) >>> 0) |
            ((s4 & 0xff000000) >>> 24)
    s[1] += ((((s7 & 0x0000ff00) | (s6 & 0x000000ff)) << 16) >>> 0) |
            (((s5 & 0xff000000) | (s4 & 0x00ff0000)) >>> 16)
    s[0] += (((s7 & 0x000000ff) << 24) >>> 0) |
            (((s6 & 0xff000000) | (s5 & 0x00ff0000) | (s4 & 0x0000ff00)) >>> 8)
  } else if (widthBits === 160) {
    s[4] += ((s7 & 0xfe000000) | (s6 & 0x01f80000) | (s5 & 0x0007f000)) >>> 12
    s[3] += ((s7 & 0x01f80000) | (s6 & 0x0007f000) | (s5 & 0x00000fc0)) >>> 6
    s[2] += (s7 & 0x0007f000) | (s6 & 0x00000fc0) | (s5 & 0x0000003f)
    s[1] += rotr(((s7 & 0x00000fc0) | (s6 & 0x0000003f) | (s5 & 0xfe000000)) >>> 0, 25)
    s[0] += rotr(((s7 & 0x0000003f) | (s6 & 0xfe000000) | (s5 & 0x01f80000)) >>> 0, 19)
  } else if (widthBits === 192) {
    s[5] += (((s7 & 0xfc000000) | (s6 & 0x03e00000)) >>> 21)
    s[4] += (((s7 & 0x03e00000) | (s6 & 0x001f0000)) >>> 16)
    s[3] += (((s7 & 0x001f0000) | (s6 & 0x0000fc00)) >>> 10)
    s[2] += (((s7 & 0x0000fc00) | (s6 & 0x000003e0)) >>> 5)
    s[1] += (s7 & 0x000003e0) | (s6 & 0x0000001f)
    s[0] += rotr(((s7 & 0x0000001f) | (s6 & 0xfc000000)) >>> 0, 26)
  } else if (widthBits === 224) {
    s[6] += s7 & 0x0000000f
    s[5] += (s7 >>> 4) & 0x0000001f
    s[4] += (s7 >>> 9) & 0x0000000f
    s[3] += (s7 >>> 13) & 0x0000001f
    s[2] += (s7 >>> 18) & 0x0000000f
    s[1] += (s7 >>> 22) & 0x0000001f
    s[0] += (s7 >>> 27) & 0x0000001f
  }
  // widthBits === 256: no folding.
}

export function haval(data, passes, widthBits) {
  if (!ORDERS[passes]) throw new Error(`haval: unsupported passes ${passes}`)
  if (![128, 160, 192, 224, 256].includes(widthBits)) {
    throw new Error(`haval: unsupported width ${widthBits}`)
  }

  const state = new Uint32Array(D0)

  // Pad to 118 mod 128 with 0x01 then zeros, then append the 10-byte tail:
  // version/passes/width byte, width byte, 64-bit little-endian bit count.
  const index = data.length & 0x7f
  const padLen = index < 118 ? 118 - index : 246 - index
  const msg = new Uint8Array(data.length + padLen + 10)
  msg.set(data, 0)
  msg[data.length] = 0x01
  const tail = msg.length - 10
  msg[tail] = (0x01 & 0x07) | ((passes & 0x07) << 3) | ((widthBits & 0x03) << 6)
  msg[tail + 1] = (widthBits >> 2) & 0xff
  const bitLenLo = (data.length << 3) >>> 0
  const bitLenHi = Math.floor(data.length / 0x20000000)
  const dv = new DataView(msg.buffer)
  dv.setUint32(tail + 2, bitLenLo, true)
  dv.setUint32(tail + 6, bitLenHi, true)

  const x = new Uint32Array(32)
  for (let off = 0; off < msg.length; off += 128) {
    for (let i = 0; i < 32; i++) x[i] = dv.getUint32(off + i * 4, true)
    transform(passes, state, x)
  }

  tailor(state, widthBits)

  const out = new Uint8Array(widthBits / 8)
  const ov = new DataView(out.buffer)
  for (let i = 0; i < out.length / 4; i++) ov.setUint32(i * 4, state[i], true)
  return out
}
