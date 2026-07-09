// Hash verification: does `password` produce `hash` for a given type?
// Extracts embedded salts/params from the hash itself and recomputes.
// Returns true/false, or null when the type cannot be verified (e.g. `null`).

import { digestHex } from './digests.js'
import { desCrypt, extDesCrypt } from './crypt/descrypt.js'
import { md5Crypt } from './crypt/md5crypt.js'
import { sha256Crypt, sha512Crypt } from './crypt/shacrypt.js'
import { scrypt } from 'hash-wasm'
import { bcryptHash, bcryptSaltToBytes, argon2Hash } from './kdf.js'
import { nthash, premysql41 } from './algos/misc.js'
import { b64ToBytes, bytesToB64, bytesToHex, concatBytes } from './b64.js'

const enc = new TextEncoder()

async function rawDigest(algo, data) {
  const hex = await digestHex[algo](data)
  const b = new Uint8Array(hex.length / 2)
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return b
}

// crypt-style spec prefix: everything up to and including the last '$'
const specOf = (hash) => hash.slice(0, hash.lastIndexOf('$') + 1)

async function verifyLdapPlain(digest, body, data) {
  return bytesToB64(await rawDigest(digest, data)) === body
}

async function verifyLdapSalted(digest, len, body, data) {
  const bytes = b64ToBytes(body)
  if (bytes.length <= len) return false
  const salt = bytes.subarray(len)
  const d = await rawDigest(digest, concatBytes(data, salt))
  return bytesToHex(d) === bytesToHex(bytes.subarray(0, len))
}

async function verifyBcrypt(hash, data) {
  const m = hash.match(/^\$(2[abxy])\$(\d{2})\$([./A-Za-z0-9]{22})([./A-Za-z0-9]{31})$/)
  if (!m) return false
  const { value } = await bcryptHash(data, {
    cost: parseInt(m[2], 10),
    variant: m[1],
    salt: bcryptSaltToBytes(m[3]),
  })
  return value === hash
}

async function verifyArgon2(hash, data) {
  const m = hash.match(/^\$(argon2id|argon2i)\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/)
  if (!m) return false
  const { value } = await argon2Hash(data, {
    type: m[1],
    memory: +m[2],
    iterations: +m[3],
    parallelism: +m[4],
    salt: b64ToBytes(m[5]),
  })
  return value === hash
}

async function verifyScrypt(hash, data) {
  const m = hash.match(/^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/)
  if (!m) return false
  const want = b64ToBytes(m[5])
  const hex = await scrypt({
    password: data,
    salt: b64ToBytes(m[4]),
    costFactor: 2 ** +m[1],
    blockSize: +m[2],
    parallelism: +m[3],
    hashLength: want.length,
    outputType: 'hex',
  })
  return hex === bytesToHex(want)
}

async function verifyPbkdf2(digest, hash, data) {
  const m = hash.match(/^\$pbkdf2-sha(?:256|512)\$i=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/)
  if (!m) return false
  const want = b64ToBytes(m[3])
  const key = await crypto.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: digest, salt: b64ToBytes(m[2]), iterations: +m[1] },
    key,
    want.length * 8,
  )
  return bytesToHex(new Uint8Array(bits)) === bytesToHex(want)
}

async function verifyUnreal(digest, hash, data) {
  const m = hash.match(/^\$([A-Za-z0-9+/]{8})\$([A-Za-z0-9+/]+=*)$/)
  if (!m) return false
  const salt = b64ToBytes(m[1])
  const inner = await rawDigest(digest, data)
  const outer = await rawDigest(digest, concatBytes(inner, salt))
  return bytesToB64(outer) === m[2]
}

export async function verifyAgainst(type, rawHash, password) {
  const hash = rawHash.trim()
  const data = enc.encode(password)

  // bare digests & checksums (hex, case-insensitive)
  if (digestHex[type]) return (await digestHex[type](data)) === hash.toLowerCase()

  switch (type) {
    case 'plain':
    case 'ldap-cleartext':
    case 'openldap-cleartext': return password === hash
    case 'ircu-plain': return '$PLAIN$' + password === hash
    case 'null': return null
    case 'premysql41': return premysql41(password) === hash.toLowerCase()
    case 'crypt-nthash': return '$3$$' + (await nthash(password)) === hash.toLowerCase()

    case 'crypt':
    case 'apache-crypt':
    case 'unreal-crypt': return desCrypt(data, hash.slice(0, 2)) === hash
    case 'crypt-ext': return extDesCrypt(data, hash.slice(0, 9)) === hash
    case 'crypt-md5': return md5Crypt(data, specOf(hash)) === hash
    case 'apache-md5': return md5Crypt(data, specOf(hash)) === hash
    case 'crypt-sha256':
    case 'apache-sha256': return sha256Crypt(data, specOf(hash)) === hash
    case 'crypt-sha512':
    case 'apache-sha512': return sha512Crypt(data, specOf(hash)) === hash

    case 'ircu-smd5': {
      const m = hash.match(/^\$SMD5\$([^$]*)\$(.*)$/)
      if (!m) return false
      return md5Crypt(data, `$1$${m[1]}$`) === `$1$${m[1]}$${m[2]}`
    }

    case 'bcrypt':
    case 'crypt-blowfish':
    case 'crypt-blowfish-2a':
    case 'crypt-blowfish-2x':
    case 'crypt-blowfish-2y':
    case 'apache-bcrypt':
    case 'unreal-bcrypt': return verifyBcrypt(hash, data)

    case 'argon2i':
    case 'argon2id':
    case 'unreal-argon2':
    case 'unreal-argon2id': return verifyArgon2(hash, data)

    case 'scrypt': return verifyScrypt(hash, data)
    case 'pbkdf2-sha256': return verifyPbkdf2('SHA-256', hash, data)
    case 'pbkdf2-sha512': return verifyPbkdf2('SHA-512', hash, data)

    case 'ldap-md5':
    case 'openldap-md5': return verifyLdapPlain('md5', hash.replace(/^\{MD5\}/i, ''), data)
    case 'ldap-sha':
    case 'openldap-sha':
    case 'apache-sha': return verifyLdapPlain('sha1', hash.replace(/^\{SHA\}/i, ''), data)
    case 'ldap-sha256': return verifyLdapPlain('sha256', hash.replace(/^\{SHA256\}/i, ''), data)
    case 'ldap-sha384': return verifyLdapPlain('sha384', hash.replace(/^\{SHA384\}/i, ''), data)
    case 'ldap-sha512': return verifyLdapPlain('sha512', hash.replace(/^\{SHA512\}/i, ''), data)

    case 'ldap-smd5':
    case 'openldap-smd5': return verifyLdapSalted('md5', 16, hash.replace(/^\{SMD5\}/i, ''), data)
    case 'ldap-ssha':
    case 'openldap-ssha': return verifyLdapSalted('sha1', 20, hash.replace(/^\{SSHA\}/i, ''), data)
    case 'ldap-ssha256': return verifyLdapSalted('sha256', 32, hash.replace(/^\{SSHA256\}/i, ''), data)
    case 'ldap-ssha384': return verifyLdapSalted('sha384', 48, hash.replace(/^\{SSHA384\}/i, ''), data)
    case 'ldap-ssha512': return verifyLdapSalted('sha512', 64, hash.replace(/^\{SSHA512\}/i, ''), data)

    case 'ldap-crypt':
    case 'openldap-crypt': return verifyAgainst('crypt', hash.replace(/^\{CRYPT\}/i, ''), password)
    case 'ldap-crypt-md5':
    case 'openldap-crypt-md5': return verifyAgainst('crypt-md5', hash.replace(/^\{CRYPT\}/i, ''), password)
    case 'ldap-crypt-ext':
    case 'openldap-crypt-ext': return verifyAgainst('crypt-ext', hash.replace(/^\{CRYPT\}/i, ''), password)
    case 'ldap-crypt-blowfish':
    case 'openldap-crypt-blowfish': return verifyAgainst('bcrypt', hash.replace(/^\{CRYPT\}/i, ''), password)

    case 'unreal-md5': return verifyUnreal('md5', hash, data)
    case 'unreal-sha1': return verifyUnreal('sha1', hash, data)
    case 'unreal-ripemd160': return verifyUnreal('ripemd160', hash, data)

    default: return null
  }
}
