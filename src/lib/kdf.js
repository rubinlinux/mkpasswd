// Password-based KDFs backed by hash-wasm (bcrypt, argon2). These return the
// standard crypt-style encoded strings, matching PHP's crypt()/password_hash().

import { bcrypt, argon2i, argon2id } from 'hash-wasm'

const BCRYPT_B64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

export function randomBytes(n) {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}

// bcrypt's own base64 (not standard) — used to render a 16-byte salt as 22 chars.
export function bcryptB64(bytes) {
  let out = ''
  let i = 0
  while (i < bytes.length) {
    let c1 = bytes[i++] & 0xff
    out += BCRYPT_B64[c1 >> 2]
    c1 = (c1 & 0x03) << 4
    if (i >= bytes.length) { out += BCRYPT_B64[c1]; break }
    let c2 = bytes[i++] & 0xff
    c1 |= (c2 >> 4) & 0x0f
    out += BCRYPT_B64[c1]
    c1 = (c2 & 0x0f) << 2
    if (i >= bytes.length) { out += BCRYPT_B64[c1]; break }
    c2 = bytes[i++] & 0xff
    c1 |= (c2 >> 6) & 0x03
    out += BCRYPT_B64[c1]
    out += BCRYPT_B64[c2 & 0x3f]
  }
  return out
}

export function bcryptSaltToBytes(s22) {
  const out = new Uint8Array(16)
  let bits = 0, acc = 0, oi = 0
  for (const ch of s22) {
    const v = BCRYPT_B64.indexOf(ch)
    if (v < 0) continue
    acc = (acc << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[oi++] = (acc >> bits) & 0xff
      if (oi === 16) break
    }
  }
  return out
}

// password: Uint8Array. variant: '2a' | '2b' | '2x' | '2y'. salt: 16 bytes.
export async function bcryptHash(password, { cost = 10, variant = '2y', salt } = {}) {
  const saltBytes = salt ?? randomBytes(16)
  const encoded = await bcrypt({
    password: password.length > 72 ? password.slice(0, 72) : password, // bcrypt truncates at 72 bytes
    salt: saltBytes,
    costFactor: cost,
    outputType: 'encoded',
  })
  // hash-wasm emits $2b$; relabel to the requested variant (2a/2x/2y share output for 7-bit input).
  return { value: encoded.replace(/^\$2[abxy]\$/, `$${variant}$`), salt: saltBytes }
}

export async function argon2Hash(password, {
  type = 'argon2id', memory = 65536, iterations = 4, parallelism = 1, salt,
} = {}) {
  const saltBytes = salt ?? randomBytes(16)
  const fn = type === 'argon2i' ? argon2i : argon2id
  const value = await fn({
    password,
    salt: saltBytes,
    parallelism,
    iterations,
    memorySize: memory,
    hashLength: 32,
    outputType: 'encoded',
  })
  return { value, salt: saltBytes }
}
