// Compute dispatch: (type, password, opts) -> { value, salt? }.
// Pure and isomorphic — runs identically on the main thread or in the worker.
// Salted/KDF types accept opts.salt to reproduce a specific hash; otherwise a
// fresh random salt is generated and returned so the UI can display/lock it.

import { digestHex } from './digests.js'
import { desCrypt, extDesCrypt } from './crypt/descrypt.js'
import { md5Crypt } from './crypt/md5crypt.js'
import { sha256Crypt, sha512Crypt } from './crypt/shacrypt.js'
import { bcryptHash, argon2Hash, randomBytes } from './kdf.js'
import { nthash, premysql41 } from './algos/misc.js'
import { bytesToB64, hexToBytes, concatBytes } from './b64.js'

const enc = new TextEncoder()
const CRYPT_B64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

function saltString(n, salt) {
  if (salt) return salt
  const b = randomBytes(n)
  let s = ''
  for (const x of b) s += CRYPT_B64[x & 63]
  return s
}

async function rawDigest(type, data) {
  return hexToBytes(await digestHex[type](data))
}

// ---- LDAP / RFC 2307 scheme helpers ---------------------------------------
async function ldapPlain(scheme, digest, data) {
  return `{${scheme}}` + bytesToB64(await rawDigest(digest, data))
}
async function ldapSalted(scheme, digest, data, saltHex) {
  const salt = saltHex ? hexToBytes(saltHex) : randomBytes(8)
  const d = await rawDigest(digest, concatBytes(data, salt))
  return { value: `{${scheme}}` + bytesToB64(concatBytes(d, salt)), salt: bytesToHex(salt) }
}
function bytesToHex(b) {
  let s = ''
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s
}

// ---- crypt() spec builders -------------------------------------------------
function desSalt(salt) { return saltString(2, salt) }
function md5Salt(salt) { return saltString(8, salt) }
function shaSalt(salt) { return saltString(8, salt) }

// The main entry point. Returns { value, salt } (salt may be undefined).
export async function compute(type, password, opts = {}) {
  const data = enc.encode(password)
  const P = opts.params ?? {}

  // digests & checksums --------------------------------------------------
  if (digestHex[type]) {
    return { value: await digestHex[type](data) }
  }

  switch (type) {
    // specials -----------------------------------------------------------
    case 'plain': return { value: password }
    case 'null': return { value: '<null>' } // site emits the literal string, ignoring input
    case 'premysql41': return { value: premysql41(password) }

    // crypt family -------------------------------------------------------
    case 'crypt':
    case 'apache-crypt':
    case 'unreal-crypt': {
      const salt = desSalt(opts.salt)
      return { value: desCrypt(data, salt), salt }
    }
    case 'crypt-ext': {
      const rounds = clamp(P.rounds ?? 25000, 1, 0xffffff)
      const salt = opts.salt ?? (encExtRounds(rounds) + saltString(4))
      return { value: extDesCrypt(data, '_' + salt), salt }
    }
    case 'crypt-md5': {
      const salt = md5Salt(opts.salt)
      return { value: md5Crypt(data, `$1$${salt}$`), salt }
    }
    case 'apache-md5': {
      const salt = md5Salt(opts.salt)
      return { value: md5Crypt(data, `$apr1$${salt}$`), salt }
    }
    case 'crypt-sha256':
    case 'apache-sha256': {
      const salt = shaSalt(opts.salt)
      const rounds = P.rounds ?? 5000
      const spec = rounds === 5000 ? `$5$${salt}$` : `$5$rounds=${rounds}$${salt}$`
      return { value: sha256Crypt(data, spec), salt }
    }
    case 'crypt-sha512':
    case 'apache-sha512': {
      const salt = shaSalt(opts.salt)
      const rounds = P.rounds ?? 5000
      const spec = rounds === 5000 ? `$6$${salt}$` : `$6$rounds=${rounds}$${salt}$`
      return { value: sha512Crypt(data, spec), salt }
    }
    case 'crypt-nthash':
      return { value: '$3$$' + (await nthash(password)) }

    // bcrypt variants ----------------------------------------------------
    case 'bcrypt':
    case 'crypt-blowfish':
    case 'crypt-blowfish-2y':
    case 'apache-bcrypt':
    case 'unreal-bcrypt':
      return bcryptVariant(data, '2y', P, opts)
    case 'crypt-blowfish-2a':
      return bcryptVariant(data, '2a', P, opts)
    case 'crypt-blowfish-2x':
      return bcryptVariant(data, '2x', P, opts)

    // argon2 -------------------------------------------------------------
    case 'argon2i':
      return argonVariant(data, 'argon2i', P, opts)
    case 'argon2id':
    case 'unreal-argon2id':
      return argonVariant(data, 'argon2id', P, opts)
    case 'unreal-argon2':
      return argonVariant(data, 'argon2id', P, opts) // UnrealIRCd default is argon2id

    // LDAP unsalted ------------------------------------------------------
    case 'ldap-cleartext':
    case 'openldap-cleartext':
      return { value: password }
    case 'ldap-md5':
    case 'openldap-md5': return { value: await ldapPlain('MD5', 'md5', data) }
    case 'ldap-sha':
    case 'openldap-sha': return { value: await ldapPlain('SHA', 'sha1', data) }
    case 'ldap-sha256': return { value: await ldapPlain('SHA256', 'sha256', data) }
    case 'ldap-sha384': return { value: await ldapPlain('SHA384', 'sha384', data) }
    case 'ldap-sha512': return { value: await ldapPlain('SHA512', 'sha512', data) }

    // LDAP salted --------------------------------------------------------
    case 'ldap-smd5':
    case 'openldap-smd5': return await ldapSalted('SMD5', 'md5', data, opts.salt)
    case 'ldap-ssha':
    case 'openldap-ssha': return await ldapSalted('SSHA', 'sha1', data, opts.salt)
    case 'ldap-ssha256': return await ldapSalted('SSHA256', 'sha256', data, opts.salt)
    case 'ldap-ssha384': return await ldapSalted('SSHA384', 'sha384', data, opts.salt)
    case 'ldap-ssha512': return await ldapSalted('SSHA512', 'sha512', data, opts.salt)

    // LDAP {CRYPT} wrappers ---------------------------------------------
    case 'ldap-crypt':
    case 'openldap-crypt': {
      const r = await compute('crypt', password, opts)
      return { value: '{CRYPT}' + r.value, salt: r.salt }
    }
    case 'ldap-crypt-md5':
    case 'openldap-crypt-md5': {
      const r = await compute('crypt-md5', password, opts)
      return { value: '{CRYPT}' + r.value, salt: r.salt }
    }
    case 'ldap-crypt-ext':
    case 'openldap-crypt-ext': {
      const r = await compute('crypt-ext', password, opts)
      return { value: '{CRYPT}' + r.value, salt: r.salt }
    }
    case 'ldap-crypt-blowfish':
    case 'openldap-crypt-blowfish': {
      const r = await compute('bcrypt', password, opts)
      return { value: '{CRYPT}' + r.value, salt: r.salt }
    }

    // Apache {SHA} -------------------------------------------------------
    case 'apache-sha': return { value: await ldapPlain('SHA', 'sha1', data) }

    // IRC daemons --------------------------------------------------------
    case 'ircu-plain': return { value: '$PLAIN$' + password }
    case 'ircu-smd5': {
      // Nefarious SMD5: standard md5crypt with internal magic $1$, re-tagged $SMD5$.
      const salt = saltString(2, opts.salt)
      const body = md5Crypt(data, `$1$${salt}$`).slice(3) // drop "$1$"
      return { value: '$SMD5$' + body, salt }
    }
    case 'unreal-md5': return await unrealSalted('md5', password, opts.salt)
    case 'unreal-sha1': return await unrealSalted('sha1', password, opts.salt)
    case 'unreal-ripemd160': return await unrealSalted('ripemd160', password, opts.salt)

    default:
      throw new Error(`unknown hash type: ${type}`)
  }
}

function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)) }

// BSDi extended-DES iteration count as 4 crypt-base64 chars (little-endian 6-bit).
function encExtRounds(n) {
  let s = ''
  for (let i = 0; i < 4; i++) { s += CRYPT_B64[n & 63]; n >>= 6 }
  return s
}

async function bcryptVariant(data, variant, P, opts) {
  const r = await bcryptHash(data, { cost: P.cost ?? 10, variant, salt: opts.saltBytes })
  return { value: r.value, saltBytes: r.salt }
}

async function argonVariant(data, type, P, opts) {
  const r = await argon2Hash(data, {
    type,
    memory: P.memory ?? 65536,
    iterations: P.iterations ?? 4,
    parallelism: P.parallelism ?? 1,
    salt: opts.saltBytes,
  })
  return { value: r.value, saltBytes: r.salt }
}

// UnrealIRCd salted digest (verified in reference/wrapper-formats.md):
//   $<b64(salt)>$<b64( HASH( HASH(password) + salt ) )>, salt = 6 raw bytes.
async function unrealSalted(digest, password, saltHex) {
  const salt = saltHex ? hexToBytes(saltHex) : randomBytes(6)
  const inner = await rawDigest(digest, enc.encode(password))
  const outer = await rawDigest(digest, concatBytes(inner, salt))
  return { value: `$${bytesToB64(salt)}$${bytesToB64(outer)}`, salt: bytesToHex(salt) }
}
