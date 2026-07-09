// Verify all JS/WASM hash implementations against PHP-generated ground truth.
// Usage: node tests/check.mjs [nameprefix ...]   e.g. node tests/check.mjs tiger gost
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bcrypt, argon2id, argon2i } from 'hash-wasm'
import { digestHex } from '../src/lib/digests.js'
import { desCrypt, extDesCrypt } from '../src/lib/crypt/descrypt.js'
import { md5Crypt } from '../src/lib/crypt/md5crypt.js'
import { sha256Crypt, sha512Crypt } from '../src/lib/crypt/shacrypt.js'
import { nthash, premysql41 } from '../src/lib/algos/misc.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8'))
const cv = JSON.parse(readFileSync(join(here, 'crypt-vectors.json'), 'utf8'))

const filters = process.argv.slice(2)
const match = (name) => filters.length === 0 || filters.some((f) => name.startsWith(f))
const hexToBytes = (hex) => {
  const b = new Uint8Array(hex.length / 2)
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return b
}

let pass = 0
let fail = 0
const skipped = new Set()
const failures = []

function record(name, id, want, got) {
  if (got === want) {
    pass++
  } else {
    fail++
    failures.push({ name, id, want, got })
  }
}

async function tryCase(name, id, want, fn) {
  try {
    record(name, id, want, await fn())
  } catch (e) {
    if (/not implemented/.test(String(e))) skipped.add(name)
    else record(name, id, want, `EXCEPTION: ${e.message}`)
  }
}

// --- digests ---------------------------------------------------------------
for (const [algo, cases] of Object.entries(vectors.digests)) {
  if (!match(algo)) continue
  const fn = digestHex[algo]
  if (!fn) { skipped.add(algo); continue }
  for (const [id, want] of Object.entries(cases)) {
    await tryCase(algo, id, want, () => fn(hexToBytes(vectors.inputs[id])))
  }
}

// --- crypt family ----------------------------------------------------------
const CRYPT_FNS = {
  std_des: desCrypt,
  ext_des: extDesCrypt,
  md5: md5Crypt,
  apr1: md5Crypt,
  sha256: sha256Crypt,
  sha512: sha512Crypt,
}

const B64_BCRYPT = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
function bcryptSaltBytes(s22) {
  const out = new Uint8Array(16)
  let bits = 0
  let acc = 0
  let oi = 0
  for (const ch of s22) {
    acc = (acc << 6) | B64_BCRYPT.indexOf(ch)
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[oi++] = (acc >> bits) & 0xff
      if (oi === 16) break
    }
  }
  return out
}

let knownDivergence = 0
for (const v of cv.crypt) {
  if (!match(v.type)) continue
  const pw = hexToBytes(v.password_hex)
  if (v.type.startsWith('blowfish_')) {
    const m = v.hash.match(/^\$(2[axy])\$(\d\d)\$(.{22})/)
    const got = await bcrypt({
      password: pw.slice(0, 72), // PHP/bcrypt truncates at 72 bytes
      salt: bcryptSaltBytes(m[3]),
      costFactor: parseInt(m[2], 10),
      outputType: 'encoded',
    })
    const normalized = got.replace(/^\$2[abxy]\$/, `$${m[1]}$`)
    if (m[1] === '2x' && pw.some((b) => b >= 0x80) && normalized !== v.hash) {
      knownDivergence++ // $2x$ sign-extension bug is intentionally not replicated
      continue
    }
    // apr1 salt spec needs the magic prefix re-attached for md5Crypt
    record(v.type, v.salt, v.hash, normalized)
    continue
  }
  const fn = CRYPT_FNS[v.type]
  const saltSpec = v.type === 'apr1' ? `$apr1$${v.salt}$` : v.salt
  await tryCase(v.type, v.salt, v.hash, () => fn(pw, saltSpec))
}

// --- specials ----------------------------------------------------------------
if (match('nthash')) {
  for (const [pwHex, want] of Object.entries(cv.specials.nthash)) {
    await tryCase('nthash', pwHex, want, () => nthash(new TextDecoder().decode(hexToBytes(pwHex))))
  }
}
if (match('premysql41')) {
  for (const [pwHex, want] of Object.entries(cv.specials.premysql41)) {
    await tryCase('premysql41', pwHex, want, async () => premysql41(new TextDecoder().decode(hexToBytes(pwHex))))
  }
}

// --- argon2 (recompute raw hash from PHP's encoded output) -------------------
if (match('argon2')) {
  for (const [algo, encoded] of Object.entries(cv.argon2 ?? {})) {
    const m = encoded.match(/^\$(argon2id?)\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/)
    if (!m) { record(algo, 'parse', encoded, 'UNPARSEABLE'); continue }
    const salt = Uint8Array.from(Buffer.from(m[5], 'base64'))
    const wantHash = Buffer.from(m[6], 'base64').toString('hex')
    const fn = m[1] === 'argon2id' ? argon2id : argon2i
    await tryCase(algo, 'recompute', wantHash, () => fn({
      password: 'password',
      salt,
      parallelism: parseInt(m[4], 10),
      iterations: parseInt(m[3], 10),
      memorySize: parseInt(m[2], 10),
      hashLength: Buffer.from(m[6], 'base64').length,
      outputType: 'hex',
    }))
  }
}

// --- scrypt / PBKDF2 vs node:crypto ground truth -------------------------------
if (match('scrypt') || match('pbkdf2') || filters.length === 0) {
  const { scryptHash, pbkdf2Hash } = await import('../src/lib/kdf.js')
  const { scryptSync, pbkdf2Sync } = await import('node:crypto')
  const { b64ToBytes, bytesToHex } = await import('../src/lib/b64.js')
  const enc = new TextEncoder()
  const kdfCases = [
    ['password', '0123456789abcdef'],
    ['', 'fedcba9876543210'],
    ['pässword™ with a much longer body 0123456789', '00112233445566778899aabbccddeeff'],
  ]
  for (const [pw, saltHex] of kdfCases) {
    const salt = hexToBytes(saltHex)
    const sOurs = await scryptHash(enc.encode(pw), { ln: 14, r: 8, p: 1, salt })
    const sWant = scryptSync(Buffer.from(pw, 'utf8'), salt, 32, { N: 2 ** 14, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }).toString('hex')
    record('scrypt', JSON.stringify(pw), sWant, bytesToHex(b64ToBytes(sOurs.value.split('$')[4])))
    record('scrypt-format', JSON.stringify(pw), '$scrypt$ln=14,r=8,p=1$', sOurs.value.slice(0, 22))
    for (const dig of ['sha256', 'sha512']) {
      const iters = 12000
      const ours = await pbkdf2Hash(enc.encode(pw), { digest: dig === 'sha512' ? 'SHA-512' : 'SHA-256', iterations: iters, salt })
      const want = pbkdf2Sync(Buffer.from(pw, 'utf8'), salt, iters, dig === 'sha512' ? 64 : 32, dig).toString('hex')
      record(`pbkdf2-${dig}`, JSON.stringify(pw), want, bytesToHex(b64ToBytes(ours.value.split('$')[4])))
    }
  }
}

// --- registry integrity: every type carries a strength score ------------------
{
  const { ALL_TYPES, TYPES } = await import('../src/lib/registry.js')
  for (const t of ALL_TYPES) {
    record('registry-strength', t, 'number', Number.isFinite(TYPES[t]?.strength) ? 'number' : String(TYPES[t]?.strength))
  }
}

// --- report ------------------------------------------------------------------
for (const f of failures.slice(0, 25)) {
  console.log(`FAIL ${f.name} [${f.id}]\n  want ${f.want}\n  got  ${f.got}`)
}
if (failures.length > 25) console.log(`... and ${failures.length - 25} more failures`)
if (skipped.size) console.log(`SKIP (not implemented): ${[...skipped].join(', ')}`)
if (knownDivergence) console.log(`known divergence ($2x$ + 8-bit chars): ${knownDivergence}`)
console.log(`\nPASS ${pass}  FAIL ${fail}  SKIPPED-FAMILIES ${skipped.size}`)
process.exit(fail ? 1 : 0)
