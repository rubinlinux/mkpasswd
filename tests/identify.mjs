// Round-trip test for identify() + verifyAgainst(): for every registry type,
// compute a hash, confirm identify() lists the type as a candidate, and
// confirm verifyAgainst() accepts the right password and rejects a wrong one.
import { ALL_TYPES } from '../src/lib/registry.js'
import { compute } from '../src/lib/hashers.js'
import { identify } from '../src/lib/identify.js'
import { verifyAgainst } from '../src/lib/verify.js'

const PASSWORD = 'correct horse battery'
const WRONG = 'wrong password'

// not identifiable from the string alone / nothing to verify
const NO_IDENTIFY = new Set(['plain', 'null', 'ldap-cleartext', 'openldap-cleartext'])
const NO_VERIFY = new Set(['null'])

// keep the KDFs quick in tests: small-but-valid params
const FAST_PARAMS = {
  argon2i: { memory: 1024, iterations: 2, parallelism: 1 },
  argon2id: { memory: 1024, iterations: 2, parallelism: 1 },
  // identify() recognizes UnrealIRCd by its exact params, which the UI supplies
  // from the registry (m=6144,t=2,p=2); compute() alone would use generic defaults
  'unreal-argon2': { memory: 6144, iterations: 2, parallelism: 2 },
  'unreal-argon2id': { memory: 6144, iterations: 2, parallelism: 2 },
  scrypt: { ln: 10, r: 8, p: 1 },
  'pbkdf2-sha256': { iterations: 5000 },
  'pbkdf2-sha512': { iterations: 5000 },
  bcrypt: { cost: 4 }, 'crypt-blowfish': { cost: 4 }, 'crypt-blowfish-2a': { cost: 4 },
  'crypt-blowfish-2x': { cost: 4 }, 'crypt-blowfish-2y': { cost: 4 },
  'apache-bcrypt': { cost: 4 }, 'unreal-bcrypt': { cost: 4 },
  'ldap-crypt-blowfish': { cost: 4 }, 'openldap-crypt-blowfish': { cost: 4 },
  'crypt-ext': { rounds: 1001 },
}

let pass = 0
let fail = 0
const problems = []
const check = (name, cond, detail) => {
  if (cond) pass++
  else { fail++; problems.push(`${name}: ${detail}`) }
}

for (const type of ALL_TYPES) {
  const { value } = await compute(type, PASSWORD, { params: FAST_PARAMS[type] })

  if (!NO_IDENTIFY.has(type)) {
    const candidates = identify(value).map((c) => c.type)
    check(`identify(${type})`, candidates.includes(type),
      `candidates [${candidates.join(', ')}] missing ${type} for ${value}`)
  }

  if (!NO_VERIFY.has(type)) {
    check(`verify(${type}, right)`, await verifyAgainst(type, value, PASSWORD) === true, `rejected its own hash ${value}`)
    // DES crypt only looks at the first 8 chars, so the wrong password must differ early
    check(`verify(${type}, wrong)`, await verifyAgainst(type, value, WRONG) === false, `accepted a wrong password for ${value}`)
  }
}

for (const p of problems.slice(0, 20)) console.log('FAIL', p)
console.log(`\nidentify/verify round-trip: PASS ${pass}  FAIL ${fail}`)
process.exit(fail ? 1 : 0)
