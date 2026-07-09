// Break a structured hash string into labeled segments (scheme prefix, cost,
// rounds, salt, digest) for the color-coded anatomy view. Returns null when a
// type has no interesting internal structure (bare digests, cleartext).
//
// Each segment: { text, part }, where `part` is one of:
//   'prefix' | 'param' | 'salt' | 'digest' | 'plain'
// Segments concatenate back to the original string exactly.

function seg(text, part) { return { text, part } }

// crypt-style "$id$[params$]salt$digest": split on '$', tag by position.
function cryptParts(hash, { id, hasRounds = false } = {}) {
  const out = []
  const parts = hash.split('$') // ['', id, (rounds=..)?, salt, digest]
  let i = 0
  // leading "$id$"
  out.push(seg('$' + parts[1] + '$', 'prefix'))
  i = 2
  if (hasRounds && /^rounds=\d+$/.test(parts[i])) {
    out.push(seg(parts[i] + '$', 'param'))
    i++
  }
  // salt then digest (some formats have empty salt, e.g. $3$$)
  if (i < parts.length - 1) {
    out.push(seg(parts[i] + '$', 'salt'))
    i++
  }
  if (i < parts.length) out.push(seg(parts[i], 'digest'))
  return out.filter((s) => s.text !== '')
}

export function anatomy(type, hash) {
  if (!hash || typeof hash !== 'string') return null

  // bcrypt: $2y$10$<22-char salt><31-char digest>
  const bc = hash.match(/^(\$2[abxy]\$)(\d{2}\$)([./A-Za-z0-9]{22})([./A-Za-z0-9]{31})$/)
  if (bc) {
    return [seg(bc[1], 'prefix'), seg(bc[2], 'param'), seg(bc[3], 'salt'), seg(bc[4], 'digest')]
  }

  // argon2 / scrypt / pbkdf2 PHC strings: $id$[v=..$]params$b64salt$b64hash
  const phc = hash.match(/^(\$[a-z0-9-]+\$)((?:v=\d+\$)?[^$]*\$)([^$]+)\$([^$]+)$/)
  if (phc && /^\$(argon2|scrypt|pbkdf2)/.test(hash)) {
    return [seg(phc[1], 'prefix'), seg(phc[2], 'param'), seg(phc[3] + '$', 'salt'), seg(phc[4], 'digest')]
  }

  // {SCHEME}base64  (LDAP / OpenLDAP / Apache {SHA})
  const ldap = hash.match(/^(\{[A-Za-z0-9]+\})(.*)$/s)
  if (ldap) {
    if (ldap[1].toUpperCase() === '{CRYPT}') {
      const inner = anatomy(type.replace(/^(open)?ldap-crypt/, 'crypt').replace('crypt-blowfish', 'bcrypt'), ldap[2])
      return [seg(ldap[1], 'prefix'), ...(inner ?? [seg(ldap[2], 'digest')])]
    }
    return [seg(ldap[1], 'prefix'), seg(ldap[2], 'digest')]
  }

  // $SMD5$salt$digest, $PLAIN$…
  if (/^\$SMD5\$/.test(hash)) return cryptParts(hash, { id: 'SMD5' })
  if (/^\$PLAIN\$/.test(hash)) {
    const m = hash.match(/^(\$PLAIN\$)(.*)$/s)
    return [seg(m[1], 'prefix'), seg(m[2], 'plain')]
  }

  // crypt() family
  if (/^\$1\$/.test(hash)) return cryptParts(hash, { id: '1' })
  if (/^\$apr1\$/.test(hash)) return cryptParts(hash, { id: 'apr1' })
  if (/^\$5\$/.test(hash)) return cryptParts(hash, { id: '5', hasRounds: true })
  if (/^\$6\$/.test(hash)) return cryptParts(hash, { id: '6', hasRounds: true })
  if (/^\$3\$\$/.test(hash)) return [seg('$3$$', 'prefix'), seg(hash.slice(4), 'digest')]

  // BSDi extended DES: "_" + 4-char rounds + 4-char salt + 11-char digest
  const ext = hash.match(/^(_)([./A-Za-z0-9]{4})([./A-Za-z0-9]{4})([./A-Za-z0-9]{11})$/)
  if (ext) return [seg(ext[1], 'prefix'), seg(ext[2], 'param'), seg(ext[3], 'salt'), seg(ext[4], 'digest')]

  // traditional DES crypt: 2-char salt + 11-char digest
  const des = hash.match(/^([./A-Za-z0-9]{2})([./A-Za-z0-9]{11})$/)
  if (des && (type === 'crypt' || type === 'apache-crypt' || type === 'unreal-crypt')) {
    return [seg(des[1], 'salt'), seg(des[2], 'digest')]
  }

  // UnrealIRCd salted digest: $b64salt$b64digest
  const unreal = hash.match(/^(\$[A-Za-z0-9+/]{8}\$)([A-Za-z0-9+/]+=*)$/)
  if (unreal && /^unreal-(md5|sha1|ripemd160)$/.test(type)) {
    return [seg(unreal[1], 'salt'), seg(unreal[2], 'digest')]
  }

  return null
}

export const PART_LABEL = {
  prefix: 'scheme',
  param: 'cost / rounds',
  salt: 'salt',
  digest: 'digest',
  plain: 'password',
}
