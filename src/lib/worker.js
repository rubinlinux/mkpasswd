// Hashing worker: keeps the main thread smooth while KDFs (bcrypt/argon2/sha-crypt)
// run. Processes a batch of jobs for a given generation, streaming each result back
// as it finishes and bailing out the moment a newer generation supersedes it.

import { compute } from './hashers.js'
import { verifyAgainst } from './verify.js'

let currentGen = 0
let currentVerify = 0

self.onmessage = async (e) => {
  const msg = e.data
  if (msg.kind === 'verify') {
    const { id, hash, password, candidates } = msg
    currentVerify = id
    for (const type of candidates) {
      if (id !== currentVerify) return // superseded
      let match = null
      try { match = await verifyAgainst(type, hash, password) } catch { match = null }
      if (id !== currentVerify) return
      self.postMessage({ kind: 'verify-result', id, type, match })
    }
    return
  }
  if (msg.kind !== 'compute') return
  const { gen, password, jobs } = msg
  currentGen = gen

  for (const job of jobs) {
    if (gen !== currentGen) return // superseded — stop early
    const started = performance.now()
    try {
      const { value, salt, saltBytes } = await compute(job.type, password, {
        params: job.params,
        salt: job.salt,
        saltBytes: job.saltBytes,
      })
      if (gen !== currentGen) return
      self.postMessage({
        kind: 'result', gen, type: job.type, value,
        salt, saltBytes, ms: Math.round(performance.now() - started),
      })
    } catch (err) {
      if (gen !== currentGen) return
      self.postMessage({ kind: 'result', gen, type: job.type, error: String(err?.message ?? err) })
    }
  }
  if (gen === currentGen) self.postMessage({ kind: 'done', gen })
}
