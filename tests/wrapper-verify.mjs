// Verify wrapper constructions against live-site ground truth from the research
// spec: recompute each with the *same* salt and require an exact match.
import { compute } from '../src/lib/hashers.js'

const b64ToHex = (t) => Buffer.from(t, 'base64').toString('hex')

// [type, opts, expected] — salts taken from reference/wrapper-formats.md examples.
const cases = [
  ['plain', {}, 'password'],
  ['null', {}, '<null>'],
  ['ircu-plain', {}, '$PLAIN$password'],
  ['crypt-nthash', {}, '$3$$8846f7eaee8fb117ad06bdd830b7586c'],
  ['ldap-md5', {}, '{MD5}X03MO1qnZdYdgyfeuILPmQ=='],
  ['ldap-sha', {}, '{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g='],
  ['ldap-sha256', {}, '{SHA256}XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg='],
  ['apache-sha', {}, '{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g='],
  ['ldap-smd5', { salt: '791179ed4006a5ca' }, '{SMD5}cqsdMAykaTXx38EGGOfFbXkRee1ABqXK'],
  ['ldap-ssha', { salt: 'c2182ba87154a61d' }, '{SSHA}4un+hVAE4puBsYk/Gcg8HEaULVrCGCuocVSmHQ=='],
  ['ldap-ssha256', { salt: 'fbee8f94d3355ff8' }, '{SSHA256}N8VtCouVWr81EAe9q7tI6xNqT0Z9uzGWjBudAJEouA777o+U0zVf+A=='],
  ['ircu-smd5', { salt: '8f' }, '$SMD5$8f$fxZuU7Ghs2YM.7/zIKZg3.'],
  ['unreal-md5', { salt: '10e9a4e047c8' }, '$EOmk4EfI$IPLxYoxJqMFYxsTIBWUXTQ=='],
  ['unreal-sha1', { salt: b64ToHex('GscdJ6yj') }, '$GscdJ6yj$8KOtGRCxNhbNVjcYJy/a0Mm34kE='],
  ['unreal-ripemd160', { salt: b64ToHex('krAUnTsR') }, '$krAUnTsR$AVxKbR5xgAXG08E7+N8Z4xCNzas='],
  ['ldap-crypt', { salt: 'yP' }, '{CRYPT}yP25ms9jObpU6'],
  ['apache-crypt', { salt: 'Ub' }, 'Ub35pFC6SA/7s'],
  ['unreal-crypt', { salt: 'h9' }, 'h9YmdNIlXVq7M'],
  ['ldap-crypt-md5', { salt: 'o4cbWOY8' }, '{CRYPT}$1$o4cbWOY8$etZ2vzcqOpwbMHF7KFPpK.'],
  ['apache-md5', { salt: 'G3isE1rj' }, '$apr1$G3isE1rj$AZhn.Gfk2cWHclk/jPHMp/'],
  ['apache-sha256', { salt: 'QbBD0DUrBscAjPVK' }, '$5$QbBD0DUrBscAjPVK$5K16FmUg2KYIPZw6iDT.1H14ChEMi6sOaGKXFs7IEk8'],
]

let pass = 0, fail = 0
for (const [type, opts, expected] of cases) {
  const { value } = await compute(type, 'password', opts)
  if (value === expected) { pass++ }
  else { fail++; console.log(`FAIL ${type}\n  want ${expected}\n  got  ${value}`) }
}
console.log(`\nwrapper vectors: PASS ${pass}  FAIL ${fail}`)
process.exit(fail ? 1 : 0)
