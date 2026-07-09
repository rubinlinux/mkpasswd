// "Copy as config line" helpers: wrap a computed hash in the line format the
// target system actually expects. Returns [{ label, sample, build(user) }] for
// a given type, or [] when no config-line format applies.

// which formats each kind of hash slots into
function formatsFor(type, value) {
  const out = []

  // Apache htpasswd: user:hash — apache-* and any bcrypt/crypt/apr1/{SHA}
  const htpasswdOk = /^(apache-|crypt-blowfish|bcrypt$)/.test(type) ||
    ['crypt', 'crypt-md5'].includes(type) || value.startsWith('$apr1$') || value.startsWith('{SHA}')
  if (htpasswdOk) {
    out.push({
      label: '.htpasswd',
      sample: `user:${value}`,
      build: (user) => `${user}:${value}`,
    })
  }

  // LDIF for LDAP userPassword values (already {SCHEME}-prefixed or {CRYPT})
  if (/^(open)?ldap-/.test(type) && !type.endsWith('cleartext')) {
    out.push({
      label: 'LDIF',
      sample: `dn: uid=user,dc=example,dc=com\nchangetype: modify\nreplace: userPassword\nuserPassword: ${value}`,
      build: (user) => `dn: uid=${user},dc=example,dc=com\nchangetype: modify\nreplace: userPassword\nuserPassword: ${value}`,
    })
  }

  // /etc/shadow line for crypt() schemes password_hash understands
  const shadowOk = /^(crypt$|crypt-md5|crypt-sha|crypt-blowfish|crypt-ext|bcrypt$|argon2|scrypt|pbkdf2)/.test(type)
  if (shadowOk) {
    out.push({
      label: '/etc/shadow',
      sample: `user:${value}:19000:0:99999:7:::`,
      build: (user) => `${user}:${value}:19000:0:99999:7:::`,
    })
  }

  return out
}

export function configLines(type, value) {
  if (!value) return []
  return formatsFor(type, value)
}
