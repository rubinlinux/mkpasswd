// Central registry: category ordering, category -> type mapping (captured from the
// original mkpasswd.net), and per-type UI metadata. The actual hashing lives in
// hashers.js; this file is pure data so both the UI and the worker can import it.

export const CATEGORIES = [
  { id: 'all', label: 'All', blurb: 'Every supported hash type.' },
  { id: 'hash', label: 'hash()', blurb: 'Raw digests from PHP hash() — checksums and cryptographic hashes.' },
  { id: 'crypt', label: 'crypt()', blurb: 'Unix crypt(3) password schemes.' },
  { id: 'php_password_hash', label: 'password_hash()', blurb: 'PHP password_hash() — modern, salted, tunable.' },
  { id: 'argon2', label: 'Argon2', blurb: 'Memory-hard winner of the Password Hashing Competition.' },
  { id: 'ldap', label: 'LDAP', blurb: 'RFC 2307 {SCHEME}-prefixed userPassword values.' },
  { id: 'openldap', label: 'OpenLDAP', blurb: 'Schemes shipped with OpenLDAP slapd.' },
  { id: 'apache', label: 'Apache', blurb: 'htpasswd / htdigest password formats.' },
  { id: 'md', label: 'MD', blurb: 'The MD-family message digests.' },
  { id: 'sha', label: 'SHA', blurb: 'SHA-1, SHA-2 and SHA-3 families.' },
  { id: 'sha1', label: 'SHA-1', blurb: 'SHA-1 only.' },
  { id: 'sha2', label: 'SHA-2', blurb: 'The SHA-2 family.' },
  { id: 'sha3', label: 'SHA-3', blurb: 'The Keccak-based SHA-3 family.' },
  { id: 'ripemd', label: 'RIPEMD', blurb: 'RIPEMD-128/160/256/320.' },
  { id: 'tiger', label: 'Tiger', blurb: 'Anderson & Biham Tiger digests.' },
  { id: 'haval', label: 'HAVAL', blurb: 'Tunable HAVAL, 3–5 passes × 5 widths.' },
  { id: 'ircu', label: 'ircu', blurb: 'Undernet ircu / IRC daemon schemes.' },
  { id: 'nefarious', label: 'Nefarious', blurb: 'Nefarious IRCu password schemes.' },
  { id: 'inspircd', label: 'InspIRCd', blurb: 'InspIRCd hashing modules.' },
  { id: 'denora', label: 'Denora', blurb: 'Denora IRC Stats schemes.' },
  { id: 'unrealircd', label: 'UnrealIRCd', blurb: 'UnrealIRCd authentication formats.' },
]

// type -> list of category ids it belongs to (inverse of the captured mapping).
export const categoryMap = {
  apache: ['apache-bcrypt', 'apache-crypt', 'apache-md5', 'apache-sha', 'apache-sha256', 'apache-sha512'],
  argon2: ['argon2i', 'argon2id'],
  crypt: ['bcrypt', 'crypt', 'crypt-blowfish', 'crypt-blowfish-2a', 'crypt-blowfish-2x', 'crypt-blowfish-2y', 'crypt-ext', 'crypt-md5', 'crypt-nthash', 'crypt-sha256', 'crypt-sha512'],
  denora: ['crypt', 'crypt-md5'],
  hash: ['adler32', 'crc32', 'crc32b', 'crc32c', 'fnv132', 'fnv164', 'fnv1a32', 'fnv1a64', 'gost', 'gost-crypto', 'haval128,3', 'haval128,4', 'haval128,5', 'haval160,3', 'haval160,4', 'haval160,5', 'haval192,3', 'haval192,4', 'haval192,5', 'haval224,3', 'haval224,4', 'haval224,5', 'haval256,3', 'haval256,4', 'haval256,5', 'joaat', 'md2', 'md4', 'md5', 'murmur3a', 'murmur3c', 'murmur3f', 'ripemd128', 'ripemd160', 'ripemd256', 'ripemd320', 'sha1', 'sha224', 'sha256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'snefru', 'snefru256', 'tiger128,3', 'tiger128,4', 'tiger160,3', 'tiger160,4', 'tiger192,3', 'tiger192,4', 'whirlpool', 'xxh128', 'xxh3', 'xxh32', 'xxh64'],
  haval: ['haval128,3', 'haval128,4', 'haval128,5', 'haval160,3', 'haval160,4', 'haval160,5', 'haval192,3', 'haval192,4', 'haval192,5', 'haval224,3', 'haval224,4', 'haval224,5', 'haval256,3', 'haval256,4', 'haval256,5'],
  inspircd: ['md5', 'ripemd160', 'sha256'],
  ircu: ['crypt', 'crypt-blowfish', 'crypt-md5', 'crypt-sha256', 'crypt-sha512', 'ircu-plain', 'ircu-smd5'],
  ldap: ['ldap-cleartext', 'ldap-crypt', 'ldap-crypt-blowfish', 'ldap-crypt-ext', 'ldap-crypt-md5', 'ldap-md5', 'ldap-sha', 'ldap-sha256', 'ldap-sha384', 'ldap-sha512', 'ldap-smd5', 'ldap-ssha', 'ldap-ssha256', 'ldap-ssha384', 'ldap-ssha512'],
  md: ['md2', 'md4', 'md5'],
  nefarious: ['bcrypt', 'crypt', 'crypt-blowfish', 'crypt-blowfish-2a', 'crypt-blowfish-2x', 'crypt-blowfish-2y', 'crypt-md5', 'crypt-sha256', 'crypt-sha512', 'ircu-plain', 'ircu-smd5'],
  openldap: ['openldap-cleartext', 'openldap-crypt', 'openldap-crypt-blowfish', 'openldap-crypt-ext', 'openldap-crypt-md5', 'openldap-md5', 'openldap-sha', 'openldap-smd5', 'openldap-ssha'],
  php_password_hash: ['argon2i', 'argon2id', 'bcrypt'],
  ripemd: ['ripemd128', 'ripemd160', 'ripemd256', 'ripemd320'],
  sha: ['sha1', 'sha224', 'sha256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'sha384', 'sha512', 'sha512/224', 'sha512/256'],
  sha1: ['sha1'],
  sha2: ['sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256'],
  sha3: ['sha3-224', 'sha3-256', 'sha3-384', 'sha3-512'],
  tiger: ['tiger128,3', 'tiger128,4', 'tiger160,3', 'tiger160,4', 'tiger192,3', 'tiger192,4'],
  unrealircd: ['unreal-argon2', 'unreal-argon2id', 'unreal-bcrypt', 'unreal-crypt', 'unreal-md5', 'unreal-ripemd160', 'unreal-sha1'],
}

// Full ordered list, including the three uncategorised specials.
export const ALL_TYPES = [
  'adler32', 'apache-bcrypt', 'apache-crypt', 'apache-md5', 'apache-sha', 'apache-sha256', 'apache-sha512',
  'argon2i', 'argon2id', 'bcrypt', 'crc32', 'crc32b', 'crc32c', 'crypt', 'crypt-blowfish', 'crypt-blowfish-2a',
  'crypt-blowfish-2x', 'crypt-blowfish-2y', 'crypt-ext', 'crypt-md5', 'crypt-nthash', 'crypt-sha256', 'crypt-sha512',
  'fnv132', 'fnv164', 'fnv1a32', 'fnv1a64', 'gost', 'gost-crypto',
  'haval128,3', 'haval128,4', 'haval128,5', 'haval160,3', 'haval160,4', 'haval160,5', 'haval192,3', 'haval192,4',
  'haval192,5', 'haval224,3', 'haval224,4', 'haval224,5', 'haval256,3', 'haval256,4', 'haval256,5',
  'ircu-plain', 'ircu-smd5', 'joaat', 'ldap-cleartext', 'ldap-crypt', 'ldap-crypt-blowfish', 'ldap-crypt-ext',
  'ldap-crypt-md5', 'ldap-md5', 'ldap-sha', 'ldap-sha256', 'ldap-sha384', 'ldap-sha512', 'ldap-smd5', 'ldap-ssha',
  'ldap-ssha256', 'ldap-ssha384', 'ldap-ssha512', 'md2', 'md4', 'md5', 'murmur3a', 'murmur3c', 'murmur3f', 'null',
  'openldap-cleartext', 'openldap-crypt', 'openldap-crypt-blowfish', 'openldap-crypt-ext', 'openldap-crypt-md5',
  'openldap-md5', 'openldap-sha', 'openldap-smd5', 'openldap-ssha', 'plain', 'premysql41', 'ripemd128', 'ripemd160',
  'ripemd256', 'ripemd320', 'sha1', 'sha224', 'sha256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'sha384',
  'sha512', 'sha512/224', 'sha512/256', 'snefru', 'snefru256', 'tiger128,3', 'tiger128,4', 'tiger160,3', 'tiger160,4',
  'tiger192,3', 'tiger192,4', 'unreal-argon2', 'unreal-argon2id', 'unreal-bcrypt', 'unreal-crypt', 'unreal-md5',
  'unreal-ripemd160', 'unreal-sha1', 'whirlpool', 'xxh128', 'xxh3', 'xxh32', 'xxh64',
]

// Param control descriptors, reused by several types.
const P = {
  bcryptCost: { key: 'cost', label: 'Cost', min: 4, max: 15, step: 1, default: 10, hint: '2^cost rounds' },
  shaRounds: { key: 'rounds', label: 'Rounds', min: 1000, max: 100000, step: 1000, default: 5000 },
  extRounds: { key: 'rounds', label: 'Iterations', min: 1, max: 16777215, step: 1000, default: 25000 },
  argonMem: { key: 'memory', label: 'Memory (KiB)', min: 8, max: 262144, step: 1024, default: 65536 },
  argonTime: { key: 'iterations', label: 'Time cost', min: 1, max: 10, step: 1, default: 4 },
  argonPar: { key: 'parallelism', label: 'Parallelism', min: 1, max: 8, step: 1, default: 1 },
}
const ARGON_PARAMS = [P.argonMem, P.argonTime, P.argonPar]
// UnrealIRCd ships tighter Argon2id defaults (m=6144, t=2, p=2).
const UNREAL_ARGON_PARAMS = [
  { ...P.argonMem, default: 6144 },
  { ...P.argonTime, default: 2 },
  { ...P.argonPar, default: 2 },
]

// kind -> badge styling handled in the UI; here we just tag each type.
// meta(kind, note, extra) builds an entry.
function meta(kind, note, extra = {}) {
  return { kind, note, salted: false, deterministic: true, params: [], ...extra }
}

const bits = (b) => ({ bits: b })

export const TYPES = {
  // ---- non-cryptographic checksums ----------------------------------------
  adler32: meta('checksum', 'Adler-32 checksum (zlib).', bits(32)),
  crc32: meta('checksum', 'CRC-32/BZIP2 (PHP hash "crc32").', bits(32)),
  crc32b: meta('checksum', 'CRC-32 (reflected, the common “crc32”).', bits(32)),
  crc32c: meta('checksum', 'CRC-32C (Castagnoli).', bits(32)),
  fnv132: meta('checksum', 'FNV-1, 32-bit.', bits(32)),
  fnv1a32: meta('checksum', 'FNV-1a, 32-bit.', bits(32)),
  fnv164: meta('checksum', 'FNV-1, 64-bit.', bits(64)),
  fnv1a64: meta('checksum', 'FNV-1a, 64-bit.', bits(64)),
  joaat: meta('checksum', 'Jenkins one-at-a-time.', bits(32)),
  murmur3a: meta('checksum', 'MurmurHash3 x86 32-bit.', bits(32)),
  murmur3c: meta('checksum', 'MurmurHash3 x86 128-bit.', bits(128)),
  murmur3f: meta('checksum', 'MurmurHash3 x64 128-bit.', bits(128)),
  xxh32: meta('checksum', 'xxHash 32-bit.', bits(32)),
  xxh64: meta('checksum', 'xxHash 64-bit.', bits(64)),
  xxh3: meta('checksum', 'XXH3 64-bit.', bits(64)),
  xxh128: meta('checksum', 'XXH3 128-bit.', bits(128)),

  // ---- MD family -----------------------------------------------------------
  md2: meta('digest', 'MD2 (RFC 1319). Broken; legacy only.', bits(128)),
  md4: meta('digest', 'MD4. Broken; legacy only.', bits(128)),
  md5: meta('digest', 'MD5. Broken for security; fine as a checksum.', bits(128)),

  // ---- SHA family ----------------------------------------------------------
  sha1: meta('digest', 'SHA-1. Collision-broken.', bits(160)),
  sha224: meta('digest', 'SHA-224 (SHA-2).', bits(224)),
  sha256: meta('digest', 'SHA-256 (SHA-2).', bits(256)),
  sha384: meta('digest', 'SHA-384 (SHA-2).', bits(384)),
  sha512: meta('digest', 'SHA-512 (SHA-2).', bits(512)),
  'sha512/224': meta('digest', 'SHA-512/224 (SHA-2, truncated).', bits(224)),
  'sha512/256': meta('digest', 'SHA-512/256 (SHA-2, truncated).', bits(256)),
  'sha3-224': meta('digest', 'SHA-3 (Keccak) 224-bit.', bits(224)),
  'sha3-256': meta('digest', 'SHA-3 (Keccak) 256-bit.', bits(256)),
  'sha3-384': meta('digest', 'SHA-3 (Keccak) 384-bit.', bits(384)),
  'sha3-512': meta('digest', 'SHA-3 (Keccak) 512-bit.', bits(512)),

  // ---- RIPEMD --------------------------------------------------------------
  ripemd128: meta('digest', 'RIPEMD-128.', bits(128)),
  ripemd160: meta('digest', 'RIPEMD-160.', bits(160)),
  ripemd256: meta('digest', 'RIPEMD-256.', bits(256)),
  ripemd320: meta('digest', 'RIPEMD-320.', bits(320)),

  // ---- other digests -------------------------------------------------------
  whirlpool: meta('digest', 'Whirlpool.', bits(512)),
  snefru: meta('digest', 'Snefru-2, 256-bit.', bits(256)),
  snefru256: meta('digest', 'Snefru-2, 256-bit.', bits(256)),
  gost: meta('digest', 'GOST R 34.11-94 (test S-boxes).', bits(256)),
  'gost-crypto': meta('digest', 'GOST R 34.11-94 (CryptoPro S-boxes).', bits(256)),

  // ---- specials ------------------------------------------------------------
  null: meta('special', 'The empty hash — always blank.'),
  plain: meta('special', 'The password, unchanged.'),
  premysql41: meta('special', 'Pre-4.1 MySQL OLD_PASSWORD().', bits(64)),
}

// Tiger + HAVAL families, generated.
for (const passes of [3, 4]) {
  for (const w of [128, 160, 192]) {
    TYPES[`tiger${w},${passes}`] = meta('digest', `Tiger ${w}-bit, ${passes} passes.`, bits(w))
  }
}
for (const passes of [3, 4, 5]) {
  for (const w of [128, 160, 192, 224, 256]) {
    TYPES[`haval${w},${passes}`] = meta('digest', `HAVAL ${w}-bit, ${passes} passes.`, bits(w))
  }
}

// ---- crypt() family --------------------------------------------------------
Object.assign(TYPES, {
  crypt: meta('crypt', 'Traditional DES crypt(3). 8-char password, 2-char salt.', { salted: true, deterministic: false }),
  'crypt-ext': meta('crypt', 'BSDi extended DES crypt.', { salted: true, deterministic: false, params: [P.extRounds] }),
  'crypt-md5': meta('crypt', 'MD5 crypt ($1$).', { salted: true, deterministic: false }),
  'crypt-sha256': meta('crypt', 'SHA-256 crypt ($5$).', { salted: true, deterministic: false, params: [P.shaRounds] }),
  'crypt-sha512': meta('crypt', 'SHA-512 crypt ($6$).', { salted: true, deterministic: false, params: [P.shaRounds] }),
  'crypt-nthash': meta('crypt', 'NT hash in crypt form ($3$$).', bits(128)),
  bcrypt: meta('bcrypt', 'bcrypt ($2y$). Truncates at 72 bytes.', { salted: true, deterministic: false, params: [P.bcryptCost] }),
  'crypt-blowfish': meta('bcrypt', 'bcrypt, $2y$ prefix.', { salted: true, deterministic: false, params: [P.bcryptCost] }),
  'crypt-blowfish-2a': meta('bcrypt', 'bcrypt, $2a$ prefix.', { salted: true, deterministic: false, params: [P.bcryptCost] }),
  'crypt-blowfish-2x': meta('bcrypt', 'bcrypt, $2x$ prefix (buggy sign-extension variant).', { salted: true, deterministic: false, params: [P.bcryptCost] }),
  'crypt-blowfish-2y': meta('bcrypt', 'bcrypt, $2y$ prefix.', { salted: true, deterministic: false, params: [P.bcryptCost] }),
})

// ---- Argon2 ----------------------------------------------------------------
Object.assign(TYPES, {
  argon2i: meta('argon2', 'Argon2i (data-independent).', { salted: true, deterministic: false, params: ARGON_PARAMS }),
  argon2id: meta('argon2', 'Argon2id (hybrid, recommended).', { salted: true, deterministic: false, params: ARGON_PARAMS }),
})

// ---- LDAP / OpenLDAP -------------------------------------------------------
const ldapNote = (s) => `RFC 2307 {${s}} userPassword value.`
Object.assign(TYPES, {
  'ldap-cleartext': meta('ldap', 'LDAP cleartext (no prefix).'),
  'ldap-md5': meta('ldap', ldapNote('MD5')),
  'ldap-smd5': meta('ldap', ldapNote('SMD5') + ' Salted.', { salted: true, deterministic: false }),
  'ldap-sha': meta('ldap', ldapNote('SHA')),
  'ldap-ssha': meta('ldap', ldapNote('SSHA') + ' Salted.', { salted: true, deterministic: false }),
  'ldap-sha256': meta('ldap', ldapNote('SHA256')),
  'ldap-ssha256': meta('ldap', ldapNote('SSHA256') + ' Salted.', { salted: true, deterministic: false }),
  'ldap-sha384': meta('ldap', ldapNote('SHA384')),
  'ldap-ssha384': meta('ldap', ldapNote('SSHA384') + ' Salted.', { salted: true, deterministic: false }),
  'ldap-sha512': meta('ldap', ldapNote('SHA512')),
  'ldap-ssha512': meta('ldap', ldapNote('SSHA512') + ' Salted.', { salted: true, deterministic: false }),
  'ldap-crypt': meta('ldap', '{CRYPT} + DES crypt.', { salted: true, deterministic: false }),
  'ldap-crypt-md5': meta('ldap', '{CRYPT} + MD5 crypt.', { salted: true, deterministic: false }),
  'ldap-crypt-blowfish': meta('ldap', '{CRYPT} + bcrypt.', { salted: true, deterministic: false, params: [P.bcryptCost] }),
  'ldap-crypt-ext': meta('ldap', '{CRYPT} + extended DES.', { salted: true, deterministic: false }),
  'openldap-cleartext': meta('ldap', 'OpenLDAP cleartext.'),
  'openldap-md5': meta('ldap', ldapNote('MD5')),
  'openldap-smd5': meta('ldap', ldapNote('SMD5') + ' Salted.', { salted: true, deterministic: false }),
  'openldap-sha': meta('ldap', ldapNote('SHA')),
  'openldap-ssha': meta('ldap', ldapNote('SSHA') + ' Salted.', { salted: true, deterministic: false }),
  'openldap-crypt': meta('ldap', '{CRYPT} + DES crypt.', { salted: true, deterministic: false }),
  'openldap-crypt-md5': meta('ldap', '{CRYPT} + MD5 crypt.', { salted: true, deterministic: false }),
  'openldap-crypt-blowfish': meta('ldap', '{CRYPT} + bcrypt.', { salted: true, deterministic: false, params: [P.bcryptCost] }),
  'openldap-crypt-ext': meta('ldap', '{CRYPT} + extended DES.', { salted: true, deterministic: false }),
})

// ---- Apache ----------------------------------------------------------------
Object.assign(TYPES, {
  'apache-md5': meta('apache', 'Apache APR1 ($apr1$) htpasswd.', { salted: true, deterministic: false }),
  'apache-bcrypt': meta('apache', 'Apache bcrypt htpasswd.', { salted: true, deterministic: false, params: [P.bcryptCost] }),
  'apache-crypt': meta('apache', 'Apache DES crypt htpasswd.', { salted: true, deterministic: false }),
  'apache-sha': meta('apache', 'Apache {SHA} htpasswd (base64 SHA-1).'),
  'apache-sha256': meta('apache', 'Apache SHA-256 crypt ($5$).', { salted: true, deterministic: false, params: [P.shaRounds] }),
  'apache-sha512': meta('apache', 'Apache SHA-512 crypt ($6$).', { salted: true, deterministic: false, params: [P.shaRounds] }),
})

// ---- IRC daemons -----------------------------------------------------------
Object.assign(TYPES, {
  'ircu-plain': meta('irc', 'Undernet ircu plaintext.'),
  'ircu-smd5': meta('irc', 'Nefarious/ircu salted MD5 ($SMD5$).', { salted: true, deterministic: false }),
  'unreal-argon2': meta('irc', 'UnrealIRCd Argon2id (m=6144, t=2, p=2).', { salted: true, deterministic: false, params: UNREAL_ARGON_PARAMS }),
  'unreal-argon2id': meta('irc', 'UnrealIRCd Argon2id (m=6144, t=2, p=2).', { salted: true, deterministic: false, params: UNREAL_ARGON_PARAMS }),
  'unreal-bcrypt': meta('irc', 'UnrealIRCd bcrypt.', { salted: true, deterministic: false, params: [P.bcryptCost] }),
  'unreal-crypt': meta('irc', 'UnrealIRCd DES crypt.', { salted: true, deterministic: false }),
  'unreal-md5': meta('irc', 'UnrealIRCd salted MD5.', { salted: true, deterministic: false }),
  'unreal-ripemd160': meta('irc', 'UnrealIRCd salted RIPEMD-160.', { salted: true, deterministic: false }),
  'unreal-sha1': meta('irc', 'UnrealIRCd salted SHA-1.', { salted: true, deterministic: false }),
})

// ---- strength: resistance to offline password cracking ----------------------
// 0-100, judged on work factor (iterations, memory hardness), salting, and the
// state of the underlying primitive. This ranks suitability for *password
// storage*, not general cryptographic quality — SHA-256 is a fine hash but a
// poor password store (unsalted and GPU-fast).
function setStrength(score, types) {
  for (const t of types) TYPES[t].strength = score
}

setStrength(95, ['argon2id'])                                    // memory-hard, tunable, current best practice
setStrength(93, ['argon2i'])                                     // memory-hard, data-independent variant
setStrength(90, ['unreal-argon2', 'unreal-argon2id'])            // argon2id with modest fixed params (m=6144)
setStrength(85, ['bcrypt', 'crypt-blowfish', 'crypt-blowfish-2a', 'crypt-blowfish-2y',
  'ldap-crypt-blowfish', 'openldap-crypt-blowfish', 'apache-bcrypt'])
setStrength(84, ['unreal-bcrypt'])
setStrength(80, ['crypt-blowfish-2x'])                           // bcrypt with the 1997 sign-extension bug
setStrength(75, ['crypt-sha512', 'apache-sha512'])               // salted, iterated, CPU-hard (not memory-hard)
setStrength(72, ['crypt-sha256', 'apache-sha256'])
setStrength(55, ['crypt-md5', 'apache-md5', 'ldap-crypt-md5', 'openldap-crypt-md5']) // salted, 1000 rounds, but MD5 core
setStrength(52, ['ircu-smd5'])                                   // md5crypt with a 2-char salt
setStrength(48, ['ldap-ssha512'])                                // salted but single-pass -> GPU-fast
setStrength(47, ['ldap-ssha384'])
setStrength(46, ['ldap-ssha256'])
setStrength(42, ['crypt-ext', 'ldap-crypt-ext', 'openldap-crypt-ext']) // iterated but DES-based
setStrength(41, ['unreal-ripemd160'])
setStrength(40, ['ldap-ssha', 'openldap-ssha', 'unreal-sha1'])   // salted SHA-1, single-ish pass
setStrength(35, ['ldap-smd5', 'openldap-smd5', 'unreal-md5'])    // salted MD5, single-ish pass
setStrength(30, ['sha3-512', 'sha3-384', 'sha512', 'sha384', 'ldap-sha512', 'ldap-sha384']) // sound but unsalted + fast
setStrength(29, ['sha3-256', 'sha256', 'sha512/256', 'whirlpool', 'ldap-sha256'])
setStrength(28, ['sha3-224', 'sha224', 'sha512/224'])
setStrength(25, ['ripemd160', 'ripemd256', 'ripemd320', 'gost', 'gost-crypto'])
setStrength(24, ['ripemd128', 'snefru', 'snefru256'])
for (const w of [128, 160, 192]) {
  setStrength(24, [`tiger${w},4`])
  setStrength(23, [`tiger${w},3`])
}
for (const w of [128, 160, 192, 224, 256]) {
  setStrength(21, [`haval${w},5`])                               // reduced-pass HAVAL has known collisions
  setStrength(19, [`haval${w},4`])
  setStrength(17, [`haval${w},3`])
}
setStrength(20, ['sha1', 'apache-sha', 'ldap-sha', 'openldap-sha']) // collision-broken, unsalted
setStrength(15, ['crypt', 'apache-crypt', 'unreal-crypt', 'ldap-crypt', 'openldap-crypt']) // DES: 8-char cap, 12-bit salt
setStrength(12, ['md5', 'ldap-md5', 'openldap-md5'])
setStrength(10, ['md4'])
setStrength(9, ['md2'])
setStrength(8, ['crypt-nthash'])                                 // unsalted MD4, pass-the-hash
setStrength(4, ['premysql41'])                                   // 64-bit, trivially cracked
setStrength(3, ['adler32', 'crc32', 'crc32b', 'crc32c', 'fnv132', 'fnv164', 'fnv1a32', 'fnv1a64',
  'joaat', 'murmur3a', 'murmur3c', 'murmur3f', 'xxh32', 'xxh64', 'xxh3', 'xxh128'])  // not cryptographic
setStrength(0, ['plain', 'ircu-plain', 'ldap-cleartext', 'openldap-cleartext', 'null'])

// Coarse tier for display; thresholds chosen so "strong" = real KDFs,
// "good" = iterated crypt schemes, "fair" = salted-but-fast, the rest weak/none.
export function strengthTier(score) {
  if (score >= 80) return 'strong'
  if (score >= 60) return 'good'
  if (score >= 35) return 'fair'
  if (score >= 5) return 'weak'
  return 'none'
}

// Human labels for each badge kind.
export const KIND_LABEL = {
  checksum: 'checksum',
  digest: 'digest',
  crypt: 'crypt',
  bcrypt: 'bcrypt',
  argon2: 'argon2',
  ldap: 'ldap',
  apache: 'apache',
  irc: 'irc',
  special: 'special',
}

export function typesForCategory(catId) {
  if (catId === 'all') return ALL_TYPES
  return categoryMap[catId] ?? []
}

export function typeMeta(type) {
  return TYPES[type] ?? meta('digest', '')
}
