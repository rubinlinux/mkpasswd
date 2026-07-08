// nthash (NT/NTLM: MD4 over UTF-16LE) and the pre-MySQL-4.1 OLD_PASSWORD() hash.

import { md4 } from 'hash-wasm'

export function utf16le(str) {
  const b = new Uint8Array(str.length * 2)
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i)
    b[2 * i] = c & 255
    b[2 * i + 1] = c >> 8
  }
  return b
}

export async function nthash(password /* string */) {
  return md4(utf16le(password))
}

const M64 = (1n << 64n) - 1n

export function premysql41(password /* string */) {
  const data = new TextEncoder().encode(password)
  let nr = 1345345333n
  let add = 7n
  let nr2 = 0x12345671n
  for (const c of data) {
    if (c === 0x20 || c === 0x09) continue // MySQL skips spaces and tabs
    const t = BigInt(c)
    nr = (nr ^ ((((nr & 63n) + add) * t) + ((nr << 8n) & M64))) & M64
    nr2 = (nr2 + (((nr2 << 8n) & M64) ^ nr)) & M64
    add += t
  }
  const hex = (v) => (v & 0x7fffffffn).toString(16).padStart(8, '0')
  return hex(nr) + hex(nr2)
}
