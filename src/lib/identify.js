// Hash identification: given a pasted hash string, return ranked candidate
// types from the registry. Prefixed formats ($1$, $2y$, {SSHA}, PHC strings…)
// identify exactly; bare hex digests can only be narrowed by length.

import { b64ToBytes } from './b64.js'

const CRYPT64 = /^[./0-9A-Za-z]+$/
const HEX = /^[0-9a-fA-F]+$/
const B64BODY = /^[A-Za-z0-9+/]+=*$/

// hex-digest candidates by hex-string length (bits / 4)
const HEX_TYPES = {
  8: ['crc32b', 'crc32', 'crc32c', 'adler32', 'fnv1a32', 'fnv132', 'joaat', 'murmur3a', 'xxh32'],
  16: ['xxh64', 'xxh3', 'fnv1a64', 'fnv164', 'premysql41'],
  32: ['md5', 'md4', 'md2', 'ripemd128', 'tiger128,3', 'tiger128,4',
    'haval128,3', 'haval128,4', 'haval128,5', 'murmur3c', 'murmur3f', 'xxh128'],
  40: ['sha1', 'ripemd160', 'tiger160,3', 'tiger160,4', 'haval160,3', 'haval160,4', 'haval160,5'],
  48: ['tiger192,3', 'tiger192,4', 'haval192,3', 'haval192,4', 'haval192,5'],
  56: ['sha224', 'sha512/224', 'sha3-224', 'haval224,3', 'haval224,4', 'haval224,5'],
  64: ['sha256', 'sha512/256', 'sha3-256', 'gost', 'gost-crypto', 'snefru256', 'snefru',
    'ripemd256', 'haval256,3', 'haval256,4', 'haval256,5'],
  80: ['ripemd320'],
  96: ['sha384', 'sha3-384'],
  128: ['sha512', 'sha3-512', 'whirlpool'],
}

// {SCHEME} -> [types, digestByteLength, salted]
const LDAP_SCHEMES = {
  MD5: { types: ['ldap-md5', 'openldap-md5'], len: 16, salted: false },
  SMD5: { types: ['ldap-smd5', 'openldap-smd5'], len: 16, salted: true },
  SHA: { types: ['ldap-sha', 'openldap-sha', 'apache-sha'], len: 20, salted: false },
  SSHA: { types: ['ldap-ssha', 'openldap-ssha'], len: 20, salted: true },
  SHA256: { types: ['ldap-sha256'], len: 32, salted: false },
  SSHA256: { types: ['ldap-ssha256'], len: 32, salted: true },
  SHA384: { types: ['ldap-sha384'], len: 48, salted: false },
  SSHA384: { types: ['ldap-ssha384'], len: 48, salted: true },
  SHA512: { types: ['ldap-sha512'], len: 64, salted: false },
  SSHA512: { types: ['ldap-ssha512'], len: 64, salted: true },
}

// inner crypt type -> {CRYPT}-wrapped LDAP types
const CRYPT_WRAP = {
  crypt: ['ldap-crypt', 'openldap-crypt'],
  'crypt-md5': ['ldap-crypt-md5', 'openldap-crypt-md5'],
  'crypt-ext': ['ldap-crypt-ext', 'openldap-crypt-ext'],
  bcrypt: ['ldap-crypt-blowfish', 'openldap-crypt-blowfish'],
}

export function identify(raw) {
  const s = raw.trim()
  if (!s) return []
  const seen = new Set()
  const out = []
  const add = (types, reason, exact = true) => {
    for (const t of Array.isArray(types) ? types : [types]) {
      if (seen.has(t)) continue
      seen.add(t)
      out.push({ type: t, reason, exact })
    }
  }

  // --- PHC / crypt-style prefixed formats ------------------------------------
  if (/^\$argon2id\$/.test(s)) {
    add(['argon2id'], 'Argon2id PHC string')
    if (/m=6144,t=2,p=2/.test(s)) add(['unreal-argon2id', 'unreal-argon2'], 'UnrealIRCd Argon2id parameters (m=6144, t=2, p=2)')
  } else if (/^\$argon2i\$/.test(s)) {
    add(['argon2i'], 'Argon2i PHC string')
  } else if (/^\$scrypt\$/.test(s)) {
    add(['scrypt'], 'scrypt PHC string')
  } else if (/^\$pbkdf2-sha256\$/.test(s)) {
    add(['pbkdf2-sha256'], 'PBKDF2-HMAC-SHA-256 PHC string')
  } else if (/^\$pbkdf2-sha512\$/.test(s)) {
    add(['pbkdf2-sha512'], 'PBKDF2-HMAC-SHA-512 PHC string')
  } else if (/^\$2([abxy])\$\d{2}\$[./A-Za-z0-9]{53}$/.test(s)) {
    const v = s[2]
    const map = {
      a: [['crypt-blowfish-2a'], 'bcrypt, $2a$ prefix'],
      b: [['bcrypt', 'crypt-blowfish'], 'bcrypt, modern $2b$ prefix'],
      x: [['crypt-blowfish-2x'], 'bcrypt, buggy $2x$ prefix'],
      y: [['bcrypt', 'crypt-blowfish', 'crypt-blowfish-2y', 'apache-bcrypt', 'unreal-bcrypt'], 'bcrypt, $2y$ prefix'],
    }
    add(...map[v])
  } else if (/^\$1\$[^$]{0,8}\$[./0-9A-Za-z]{22}$/.test(s)) {
    add(['crypt-md5', 'ldap-crypt-md5'], 'MD5 crypt ($1$)')
  } else if (/^\$apr1\$[^$]{0,8}\$[./0-9A-Za-z]{22}$/.test(s)) {
    add(['apache-md5'], 'Apache APR1 htpasswd ($apr1$)')
  } else if (/^\$5\$(rounds=\d+\$)?[^$]{0,16}\$[./0-9A-Za-z]{43}$/.test(s)) {
    add(['crypt-sha256', 'apache-sha256'], 'SHA-256 crypt ($5$)')
  } else if (/^\$6\$(rounds=\d+\$)?[^$]{0,16}\$[./0-9A-Za-z]{86}$/.test(s)) {
    add(['crypt-sha512', 'apache-sha512'], 'SHA-512 crypt ($6$)')
  } else if (/^\$3\$\$[0-9a-fA-F]{32}$/.test(s)) {
    add(['crypt-nthash'], 'NT hash in crypt form ($3$$)')
  } else if (/^\$SMD5\$[^$]{0,8}\$[./0-9A-Za-z]{22}$/.test(s)) {
    add(['ircu-smd5'], 'Nefarious/ircu salted MD5 ($SMD5$)')
  } else if (/^\$PLAIN\$/.test(s)) {
    add(['ircu-plain'], 'ircu $PLAIN$ pseudo-hash')
  } else if (/^_[./0-9A-Za-z]{19}$/.test(s)) {
    add(['crypt-ext', 'ldap-crypt-ext'], 'BSDi extended DES crypt (_ prefix, 19 chars)')
  } else if (/^\{(\w+)\}/.test(s)) {
    // --- RFC 2307 {SCHEME} wrappers -----------------------------------------
    const m = s.match(/^\{(\w+)\}(.*)$/s)
    const scheme = m[1].toUpperCase()
    const body = m[2]
    if (scheme === 'CRYPT') {
      for (const inner of identify(body)) {
        const wrapped = CRYPT_WRAP[inner.type]
        if (wrapped) add(wrapped, `{CRYPT} wrapper around ${inner.reason}`)
      }
    } else if (LDAP_SCHEMES[scheme] && B64BODY.test(body)) {
      const spec = LDAP_SCHEMES[scheme]
      const n = b64ToBytes(body).length
      if (spec.salted ? n > spec.len : n === spec.len) {
        add(spec.types, `RFC 2307 {${scheme}} value` + (spec.salted ? ` (${n - spec.len}-byte salt)` : ''))
      }
    }
  } else if (/^\$[A-Za-z0-9+/]{8}\$[A-Za-z0-9+/]+=*$/.test(s)) {
    // --- UnrealIRCd salted digest: $b64(salt6)$b64(digest) -------------------
    const n = b64ToBytes(s.split('$')[2]).length
    if (n === 16) add(['unreal-md5'], 'UnrealIRCd salted MD5 (6-byte salt, 16-byte digest)')
    if (n === 20) add(['unreal-sha1', 'unreal-ripemd160'], 'UnrealIRCd salted digest (6-byte salt, 20-byte digest)')
  } else if (s.length === 13 && CRYPT64.test(s)) {
    add(['crypt', 'apache-crypt', 'unreal-crypt', 'ldap-crypt'], 'traditional DES crypt (13 chars, 2-char salt)')
  }

  // --- bare hex digests, narrowed by length only ------------------------------
  if (out.length === 0 && HEX.test(s) && HEX_TYPES[s.length]) {
    const bits = s.length * 4
    add(HEX_TYPES[s.length], `bare ${bits}-bit hex digest — length match only`, false)
  }

  return out
}
