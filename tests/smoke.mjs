// Runtime smoke test for the compute dispatch (types not blocked on the crypt agent).
import { compute } from '../src/lib/hashers.js'

const types = [
  'md5', 'sha256', 'sha3-256', 'tiger192,3', 'whirlpool', 'crc32', 'xxh64',
  'plain', 'null', 'premysql41', 'crypt-nthash',
  'ldap-md5', 'ldap-sha', 'ldap-sha256', 'ldap-ssha', 'ldap-ssha512', 'ldap-cleartext',
  'bcrypt', 'crypt-blowfish-2a', 'argon2id', 'argon2i',
  'unreal-sha1', 'unreal-md5', 'unreal-ripemd160',
]
for (const t of types) {
  try {
    const r = await compute(t, 'password', {})
    console.log(`${t.padEnd(18)} ${JSON.stringify(r.value).slice(0, 70)}${r.salt ? '  salt=' + r.salt : ''}`)
  } catch (e) {
    console.log(`${t.padEnd(18)} ERROR ${e.message}`)
  }
}
// determinism check with memoized salt
const a = await compute('ldap-ssha', 'password', {})
const b = await compute('ldap-ssha', 'password', { salt: a.salt })
console.log('\nssha salt-reuse stable:', a.value === b.value)
const c = await compute('bcrypt', 'password', {})
const d = await compute('bcrypt', 'password', { saltBytes: c.saltBytes })
console.log('bcrypt salt-reuse stable:', c.value === d.value)
