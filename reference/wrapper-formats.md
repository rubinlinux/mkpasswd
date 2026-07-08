# mkpasswd.net wrapper hash formats

Reverse-engineered from the live site (https://mkpasswd.net/index.php, POST
`data`/`type`/`action=Hash`). Every construction below was reproduced offline
with the salt extracted from a real live output (`hash-wasm`, node `crypto`,
and perl `libxcrypt` for the `crypt()` families). Ground-truth samples are in
`wrapper-probes.json`.

## Global behaviour

- **Empty password**: for EVERY type the site returns an empty string (`""`) —
  it does not hash the empty input at all. Reimplementations should mirror this
  (produce nothing / no output for empty input).
- **Random salt**: for salted types the three repeated `password` probes
  (`password`, `password#2`, `password#3`) all differ, confirming a fresh random
  salt per call.
- **Base64 alphabets referenced below**
  - `STD` = RFC 4648 standard `A-Za-z0-9+/` (with `=` padding unless noted).
  - `CRYPT` = crypt/modular alphabet `./0-9A-Za-z` (`.`=0, `/`=1, `0`=2 …), no padding.
    md5crypt/sha-crypt/bcrypt each use `CRYPT` with their own bit-ordering (handled
    by the standard crypt implementation).
- **openldap-\* == ldap-\***: every `openldap-*` type produces output
  byte-identical in format to its `ldap-*` counterpart (same prefix, same
  construction). They are listed together.

---

### plain
- Construction: `output = password` (verbatim, no transform, no prefix).
- Salt: none. Base64: n/a.
- Verified: yes (trivial identity).
- Example: `password` => `password`; `abc` => `abc`.
- Notes: empty => `""`.

### null
- Construction: literal constant string `<null>` for ANY non-empty password
  (password content is ignored).
- Salt: none. Base64: n/a.
- Verified: yes.
- Example: `password` => `<null>`; `a` => `<null>`.
- Notes: empty => `""`. (In the raw HTML the value attribute is `&lt;null&gt;`;
  the displayed/actual value is `<null>`.)

### crypt-nthash
- Construction: `"$3$$" + lowercase_hex( md4( password_as_UTF-16LE ) )`.
  (NT hash; the `$3$` scheme uses an empty salt field, hence the doubled `$`.)
- Salt: none. Encoding: lowercase hex (32 chars).
- Verified: yes (matches `md4(utf16le(pw))`).
- Example: `password` => `$3$$8846f7eaee8fb117ad06bdd830b7586c`.
- Notes: empty => `""`.

---

## LDAP / OpenLDAP RFC-2307 wrappers

### ldap-cleartext / openldap-cleartext
- Construction: `output = password` (verbatim, no prefix — same as `plain`).
- Verified: yes. Example: `password` => `password`.

### ldap-md5 / openldap-md5
- Construction: `"{MD5}" + base64_STD( md5_raw(password) )`.
- Salt: none. Base64: STD, padded.
- Verified: yes. Example: `password` => `{MD5}X03MO1qnZdYdgyfeuILPmQ==`.

### ldap-smd5 / openldap-smd5
- Construction: `"{SMD5}" + base64_STD( md5_raw(password + salt) + salt )`
  (digest first, then the raw salt appended, then base64 the whole thing).
- Salt: **8 raw random bytes** (full 0x00–0xFF range; NOT restricted to printable).
- Base64: STD. (16-byte digest + 8-byte salt = 24 bytes → 32 chars, no `=`.)
- Verified: yes — pw+salt order confirmed (salt+pw fails).
- Example: `password`, salt=`791179ed4006a5ca` =>
  `{SMD5}cqsdMAykaTXx38EGGOfFbXkRee1ABqXK`  (recomputed match).

### ldap-sha / openldap-sha
- Construction: `"{SHA}" + base64_STD( sha1_raw(password) )`.
- Salt: none. Base64: STD, padded.
- Verified: yes. Example: `password` => `{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=`.

### ldap-ssha / openldap-ssha
- Construction: `"{SSHA}" + base64_STD( sha1_raw(password + salt) + salt )`.
- Salt: **8 raw random bytes** (arbitrary bytes), appended after the 20-byte digest.
- Base64: STD, padded. (20+8 = 28 bytes → 40 chars ending `==`.)
- Verified: yes — pw+salt confirmed.
- Example: `password`, salt=`c2182ba87154a61d` =>
  `{SSHA}4un+hVAE4puBsYk/Gcg8HEaULVrCGCuocVSmHQ==`  (recomputed match).

### ldap-sha256
- Construction: `"{SHA256}" + base64_STD( sha256_raw(password) )`.
- Salt: none. Verified: yes.
- Example: `password` => `{SHA256}XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=`.

### ldap-ssha256
- Construction: `"{SSHA256}" + base64_STD( sha256_raw(password + salt) + salt )`.
- Salt: 8 raw random bytes after the 32-byte digest. Base64 STD, padded (32+8=40 → 56 chars `==`).
- Verified: yes.
- Example: `password`, salt=`fbee8f94d3355ff8` =>
  `{SSHA256}N8VtCouVWr81EAe9q7tI6xNqT0Z9uzGWjBudAJEouA777o+U0zVf+A==`.

### ldap-sha384
- Construction: `"{SHA384}" + base64_STD( sha384_raw(password) )`.
- Verified: yes.
- Example: `password` => `{SHA384}qLZLq9CsqRpZvbt3YbQh1PK7OCgNOnW6DyHyvrxFWD1EbFmGYMlM5oDEfRnDB4On`.

### ldap-ssha384
- Construction: `"{SSHA384}" + base64_STD( sha384_raw(password + salt) + salt )`.
- Salt: 8 raw random bytes after the 48-byte digest. Base64 STD, padded (48+8=56 → 76 chars, single `=`).
- Verified: yes.
- Example: `password`, salt=`e800257df23fce09` =>
  `{SSHA384}UdSq4+mFReFqYEeHneyYdBCmrYL7D9bJlxrL1RSRI7Y/tAyb0HKwkCbI/Ws4F8nO6AAlffI/zgk=`.

### ldap-sha512
- Construction: `"{SHA512}" + base64_STD( sha512_raw(password) )`.
- Verified: yes.
- Example: `password` => `{SHA512}sQnzu7wkTrgkQZF+0G1hi5AI3Qmzvv0bXgc5THBqi7mAsdd4Xll27ASbRt9fEyavWi6m0QP9B8lThf+rDKy8hg==`.

### ldap-ssha512
- Construction: `"{SSHA512}" + base64_STD( sha512_raw(password + salt) + salt )`.
- Salt: 8 raw random bytes after the 64-byte digest. Base64 STD (64+8=72 → 96 chars, no padding).
- Verified: yes.
- Example: `password`, salt=`27be80c67fa3384f` =>
  `{SSHA512}m+ODn9jvKxhqpyy20Q30GIO2zGVdPoZq7JUf/XbK6hs4N8wi0jJx7dMkj7VPgJHWDi7G3SsTga6HCl2/+VHH6ye+gMZ/ozhP`.

### ldap-crypt / openldap-crypt
- Construction: `"{CRYPT}" + DES_crypt(password, salt)` — traditional (descrypt) crypt.
- Salt: 2 chars from `CRYPT` alphabet, random. Output = 2 salt + 11 hash = 13 chars.
- Base64: `CRYPT`. Verified: yes (perl libxcrypt reproduces exactly).
- Example: `password` => `{CRYPT}yP25ms9jObpU6` (salt `yP`).
- Notes: classic DES crypt — only the first 8 bytes of the password are significant.

### ldap-crypt-md5 / openldap-crypt-md5
- Construction: `"{CRYPT}" + md5crypt(password, salt)` with internal magic `$1$`.
  Output core: `$1$<salt>$<hash>`.
- Salt: up to 8 chars from `CRYPT` alphabet, random. Hash: 22 `CRYPT` chars.
- Verified: yes (node md5crypt reimpl reproduces exactly).
- Example: `password` => `{CRYPT}$1$o4cbWOY8$etZ2vzcqOpwbMHF7KFPpK.` (salt `o4cbWOY8`).

### ldap-crypt-blowfish / openldap-crypt-blowfish
- Construction: `"{CRYPT}" + bcrypt(password)` with prefix `$2y$`, **cost 12**.
  Output core: `$2y$12$<22-char salt><31-char hash>`.
- Salt: 16 bytes encoded as 22 bcrypt-base64 chars, random.
- Verified: yes (`bcryptVerify` true for all samples).
- Example: `password` => `{CRYPT}$2y$12$NZw5tu69xNL0fYu7u/2X8urB8ICq1eU9wYC0.yDQc0XS3GnpmTE6e`.

### ldap-crypt-ext / openldap-crypt-ext
- Construction: `"{CRYPT}" + BSDi_extended_DES_crypt(password, salt)`.
  Output core: `_` + `iiii` + `ssss` + `hhhhhhhhhhh` (20 chars total).
- Iteration field `iiii` is **fixed at `J9..`** (= 725 rounds, little-endian
  `CRYPT`-alphabet decode). Salt `ssss` = 4 random `CRYPT` chars. Hash = 11 chars.
- Verified: yes (perl libxcrypt).
- Example: `password` => `{CRYPT}_J9..CJ4qM.kLqcawBwg` (iter `J9..`=725, salt `CJ4q`).
- Notes: unlike traditional DES, extended DES uses the full password (not just 8 bytes).

---

## Apache htpasswd formats

### apache-bcrypt
- Construction: `bcrypt(password)` with prefix `$2y$`, **cost 5**. No wrapper prefix.
- Salt: 16 bytes → 22 bcrypt-base64 chars, random.
- Verified: yes (`bcryptVerify`).
- Example: `password` => `$2y$05$JfU/v2x0MTxqaQLMsSMFP.isHPK8hN6vm5K/DMOSvzwgTCCzirQhO`.

### apache-crypt
- Construction: traditional `DES_crypt(password, salt)`, raw (no prefix), 13 chars.
- Salt: 2 `CRYPT` chars. Verified: yes (perl).
- Example: `password` => `Ub35pFC6SA/7s` (salt `Ub`).
- Notes: first 8 bytes of password significant only.

### apache-md5
- Construction: **APR1** = md5crypt(password, salt) with internal magic `$apr1$`.
  Output: `$apr1$<salt>$<hash>`.
- Salt: 8 chars from `CRYPT` alphabet, random. Hash: 22 `CRYPT` chars.
- Verified: yes (node md5crypt with magic `$apr1$`).
- Example: `password` => `$apr1$G3isE1rj$AZhn.Gfk2cWHclk/jPHMp/` (salt `G3isE1rj`).

### apache-sha
- Construction: `"{SHA}" + base64_STD( sha1_raw(password) )` — byte-identical to `ldap-sha`.
- Salt: none. Verified: yes.
- Example: `password` => `{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=`.
- Notes: this is Apache's `{SHA}` htpasswd scheme (unsalted SHA-1), not a hex digest.

### apache-sha256
- Construction: **sha256crypt** `$5$<salt>$<hash>`, default rounds (5000, not emitted).
- Salt: 16 chars from `CRYPT` alphabet, random. Hash: 43 `CRYPT` chars.
- Verified: yes (perl libxcrypt).
- Example: `password` => `$5$QbBD0DUrBscAjPVK$5K16FmUg2KYIPZw6iDT.1H14ChEMi6sOaGKXFs7IEk8`.

### apache-sha512
- Construction: **sha512crypt** `$6$<salt>$<hash>`, default rounds (5000, not emitted).
- Salt: 16 chars from `CRYPT` alphabet, random. Hash: 86 `CRYPT` chars.
- Verified: yes (perl libxcrypt).
- Example: `password` => `$6$DQeQiE93.qMTXDD4$IfT8KQxHflXnDg2NkUIeVaKU8H753OSrbMe1F4NuJJi9JIedBGOD1/Q4ShaQSwIglaQwq4SshLCFAVXGbHwnk1`.

---

## IRC daemons

### ircu-plain
- Construction: `"$PLAIN$" + password` (verbatim).
- Salt: none. Verified: yes.
- Example: `password` => `$PLAIN$password`.

### ircu-smd5
- Construction: **standard FreeBSD md5crypt with internal magic `$1$`**, output
  re-tagged from `$1$` to `$SMD5$`. i.e.
  `"$SMD5$" + salt + "$" + md5crypt_hash(password, salt, magic="$1$")`.
- Salt: **2 chars** from `CRYPT` alphabet, random.
- Base64: md5crypt's custom `CRYPT` bit-ordering (`to64`), 22 chars, no padding.
- Verified: yes — the hash body equals the hash body of `crypt(pw, "$1$"+salt)`
  exactly (magic `$SMD5$` used *inside* the algorithm does NOT match; `$1$` does).
- Example: `password`, salt=`8f` => `$SMD5$8f$fxZuU7Ghs2YM.7/zIKZg3.`.
- Notes: Nefarious IRCu "SMD5". Equivalent to `$1$8f$fxZuU7Ghs2YM.7/zIKZg3.` with the
  prefix rewritten.

---

## UnrealIRCd

### unreal-argon2 / unreal-argon2id
- Construction: Argon2id encoded string:
  `"$argon2id$v=19$m=6144,t=2,p=2$" + base64_STD_nopad(salt) + "$" + base64_STD_nopad(hash)`.
- Parameters (fixed): type=argon2**id**, version=19 (0x13), memory `m=6144` KiB,
  iterations `t=2`, parallelism `p=2`, hash length 32 bytes.
- Salt: **16 bytes**; observed as printable ASCII drawn from the `./0-9A-Za-z`
  alphabet (random), stored via the standard Argon2 base64 (STD alphabet, **no padding**).
- Verified: yes (`hash-wasm` argon2id, `outputType:'encoded'` reproduces the full string).
- Example: `password` => `$argon2id$v=19$m=6144,t=2,p=2$WFJBcVZ1MVhLdVBNWTFveA$a/GYyd5ZEjANHjN1xK5wbCsXhdxkiWEAVKAaX9j/UWM`
  (salt bytes decode to ASCII `XRAqVu1XKuPMY1ox`).
- Notes: **`unreal-argon2` is an alias of `unreal-argon2id`** — both emit an
  `$argon2id$` string with identical parameters. (There is no argon2i/d variant here.)

### unreal-bcrypt
- Construction: `bcrypt(password)` prefix `$2y$`, **cost 9**, raw (no prefix).
- Salt: 16 bytes → 22 bcrypt-base64 chars, random. Verified: yes (`bcryptVerify`).
- Example: `password` => `$2y$09$mEL2VtyJWuYH2RYsTCz/UO9pBS42t2w4LWwuiAP9r3LVZdMWWv3RW`.

### unreal-crypt
- Construction: traditional `DES_crypt(password, salt)`, raw (no prefix), 13 chars.
- Salt: 2 `CRYPT` chars. Verified: yes (perl).
- Example: `password` => `h9YmdNIlXVq7M` (salt `h9`).
- Notes: first 8 bytes significant only.

### unreal-md5 / unreal-sha1 / unreal-ripemd160
- Construction (double-hash, salt appended to the raw inner digest):
  `"$" + base64_STD(salt) + "$" + base64_STD( HASH_raw( HASH_raw(password) + salt ) )`
  where `HASH` = md5 / sha1 / ripemd160 respectively.
- Salt: **6 raw random bytes**, shown as **8 standard-base64 chars** (alphabet
  includes `+` and `/`). The raw 6 salt bytes are what get concatenated to the
  inner digest.
- Base64: STD (digest padded; salt is exactly 8 chars, no padding needed).
- Verified: yes — construction `HASH(HASH_raw(pw) + salt_raw)` reproduces every
  sample; single-hash and salt-as-ASCII variants all fail.
- Examples:
  - unreal-md5: `password`, salt(b64)=`EOmk4EfI` (raw `10e9a4e047c8`) =>
    `$EOmk4EfI$IPLxYoxJqMFYxsTIBWUXTQ==`.
  - unreal-sha1: `password`, salt=`GscdJ6yj` => `$GscdJ6yj$8KOtGRCxNhbNVjcYJy/a0Mm34kE=`.
  - unreal-ripemd160: `password`, salt=`krAUnTsR` => `$krAUnTsR$AVxKbR5xgAXG08E7+N8Z4xCNzas=`.
- Notes: the inner hash is over the *raw* digest bytes of the password (not hex),
  then concatenated with the raw salt bytes and hashed again.

---

## Verification summary

| Family | Types | Method | Result |
|--------|-------|--------|--------|
| passthrough / constant | plain, null, ldap/openldap-cleartext, ircu-plain | inspection | verified |
| raw digest + prefix | ldap/openldap/apache -md5/-sha/-sha256/-sha384/-sha512 | hash-wasm | verified |
| NT hash | crypt-nthash | md4(utf16le) | verified |
| salted-append (SMD5/SSHA*) | ldap/openldap -smd5,-ssha,-ssha256,-ssha384,-ssha512 | hash-wasm | verified (pw+salt, 8 raw salt bytes) |
| md5crypt / apr1 | ldap/openldap-crypt-md5, apache-md5 | node md5crypt | verified |
| descrypt | ldap/openldap-crypt, apache-crypt, unreal-crypt | perl libxcrypt | verified |
| ext-des | ldap/openldap-crypt-ext | perl libxcrypt | verified (725 rounds, `_J9..`) |
| bcrypt | ldap/openldap-crypt-blowfish, apache-bcrypt, unreal-bcrypt | bcryptVerify | verified (costs 12/5/9) |
| sha256/512-crypt | apache-sha256, apache-sha512 | perl libxcrypt | verified |
| ircu smd5 | ircu-smd5 | node md5crypt (magic $1$) | verified |
| argon2 | unreal-argon2, unreal-argon2id | hash-wasm argon2id | verified (alias; m=6144,t=2,p=2) |
| unreal salted digest | unreal-md5, unreal-sha1, unreal-ripemd160 | hash-wasm | verified (HASH(rawHASH(pw)+salt6)) |

All 42 wrapper types reproduced offline. No type errored on the live site.
