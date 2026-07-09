// Headless end-to-end check via the Chrome DevTools Protocol (no external deps).
// Starts the preview server if :4321 isn't already serving, launches chrome,
// types a password, waits for the worker to compute, then reads back rendered
// rows + a known hash and screenshots.
import { spawn } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// must match the `base` in astro.config.mjs (site is served under a subpath);
// the trailing slash matters: relative URLs and the SW scope hang off it
const BASE = (process.env.BASE_URL || 'http://localhost:4321/mkpasswd').replace(/\/?$/, '/')
const CHROME = process.env.CHROME || 'google-chrome'
const userDir = mkdtempSync(join(tmpdir(), 'mkp-chrome-'))
const port = 9333

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function serverUp() {
  try { await fetch(BASE, { signal: AbortSignal.timeout(1000) }); return true } catch { return false }
}

let preview = null
const killPreview = () => { if (preview) { try { process.kill(-preview.pid, 'SIGKILL') } catch {} } }
if (!(await serverUp())) {
  // detached → own process group, so killing -pid also takes down npm's astro child
  preview = spawn('npm', ['run', 'preview'], { stdio: 'ignore', detached: true })
  let ok = false
  for (let i = 0; i < 100 && !ok; i++) { await sleep(200); ok = await serverUp() }
  if (!ok) { killPreview(); console.error('E2E error: preview server did not start'); process.exit(1) }
}

const chrome = spawn(CHROME, [
  '--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${port}`, `--user-data-dir=${userDir}`,
  '--window-size=1000,1400', 'about:blank',
], { stdio: 'ignore' })

async function getWsUrl() {
  for (let i = 0; i < 50; i++) {
    try {
      const list = await (await fetch(`http://localhost:${port}/json`)).json()
      const page = list.find((t) => t.type === 'page' && t.webSocketDebuggerUrl)
      if (page) return page.webSocketDebuggerUrl
    } catch {}
    await sleep(100)
  }
  throw new Error('chrome CDP not reachable')
}

function cdp(ws) {
  let id = 0
  const pending = new Map()
  ws.addEventListener('message', (e) => {
    const msg = JSON.parse(e.data)
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id)
      pending.delete(msg.id)
      msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result)
    }
  })
  return (method, params = {}) => new Promise((resolve, reject) => {
    const mid = ++id
    pending.set(mid, { resolve, reject })
    ws.send(JSON.stringify({ id: mid, method, params }))
  })
}

async function evaluate(send, expression) {
  const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval error')
  return r.result.value
}

let exitCode = 0
try {
  const wsUrl = await getWsUrl()
  const ws = new WebSocket(wsUrl)
  await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej) })
  const send = cdp(ws)
  await send('Page.enable')
  await send('Runtime.enable')

  const errors = []
  ws.addEventListener('message', (e) => {
    const m = JSON.parse(e.data)
    if (m.method === 'Runtime.exceptionThrown') {
      errors.push(m.params.exceptionDetails?.exception?.description || 'exception')
    }
  })

  const TYPE_PASSWORD = `(() => {
    const el = document.querySelector('input[type=password], input[type=text]')
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set
    setter.call(el, 'password')
    el.dispatchEvent(new Event('input', { bubbles: true }))
    return true
  })()`

  await send('Page.navigate', { url: BASE })
  await sleep(1500) // hydrate + worker init

  // type a password into the input
  await evaluate(send, TYPE_PASSWORD)

  // wait for hashes to populate
  let count = 0
  let sampleMd5 = ''
  for (let i = 0; i < 40; i++) {
    await sleep(250)
    const info = await evaluate(send, `(() => {
      const rows = [...document.querySelectorAll('.grid > div')]
      let md5 = ''
      for (const row of rows) {
        const label = row.querySelector('code')?.textContent
        if (label === 'md5') { md5 = row.querySelector('p.font-mono')?.textContent || ''; break }
      }
      return { rowCount: rows.length, md5 }
    })()`)
    count = info.rowCount
    sampleMd5 = info.md5
    if (sampleMd5) break
  }

  // PWA: manifest resolves and the service worker registers
  let pwa = { sw: false, manifest: 0 }
  for (let i = 0; i < 20 && !pwa.sw; i++) {
    await sleep(250)
    pwa = await evaluate(send, `(async () => {
      const reg = await navigator.serviceWorker.getRegistration()
      const manifest = await fetch(new URL('manifest.webmanifest', document.baseURI)).then((r) => r.status).catch(() => 0)
      return { sw: !!reg, manifest }
    })()`)
  }

  // default sort is by strength: a memory-hard KDF tops the list
  const firstByStrength = await evaluate(send, `document.querySelector('.grid > div code')?.textContent || ''`)

  // clicking the "name" header re-sorts alphabetically
  await evaluate(send, `(() => {
    [...document.querySelectorAll('button')].find(b => b.textContent.trim().startsWith('name')).click(); return true
  })()`)
  await sleep(600)
  const firstByName = await evaluate(send, `document.querySelector('.grid > div code')?.textContent || ''`)

  // restore the default strength sort before the category checks
  await evaluate(send, `(() => {
    [...document.querySelectorAll('button')].find(b => b.textContent.trim().startsWith('strength')).click(); return true
  })()`)
  await sleep(600)

  // click the LDAP category chip and confirm the list filters down
  await evaluate(send, `(() => {
    const btn = [...document.querySelectorAll('button')].find(b => b.textContent.trim().startsWith('LDAP'))
    btn.click(); return true
  })()`)
  await sleep(1200)
  const ldap = await evaluate(send, `(() => {
    const rows = [...document.querySelectorAll('.grid > div')]
    let ldapMd5 = ''
    for (const row of rows) {
      if (row.querySelector('code')?.textContent === 'ldap-md5') { ldapMd5 = row.querySelector('p.font-mono')?.textContent || ''; break }
    }
    return { rowCount: rows.length, ldapMd5 }
  })()`)

  // clicking a chip should be reflected in the URL hash (shareable link)
  const hashAfterChip = await evaluate(send, 'location.hash')

  // header logo must actually load (catches broken base-path asset URLs)
  const logoOk = await evaluate(send, `(() => {
    const img = document.querySelector('header img')
    return !!img && img.complete && img.naturalWidth > 0
  })()`)

  const shot = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true })
  writeFileSync('tests/e2e-ldap.png', Buffer.from(shot.data, 'base64'))

  // back to All for the full-page screenshot
  await evaluate(send, `[...document.querySelectorAll('button')].find(b => b.textContent.trim().startsWith('All')).click()`)
  await sleep(1500)
  const shot2 = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true })
  writeFileSync('tests/e2e-screenshot.png', Buffer.from(shot2.data, 'base64'))

  // deep link: loading #<type-name> pre-fills the filter to exactly that type
  await send('Page.navigate', { url: `${BASE}#ldap-md5` })
  await sleep(1500)
  await evaluate(send, TYPE_PASSWORD)
  let deep = { rowCount: 0, first: '' }
  for (let i = 0; i < 20; i++) {
    await sleep(250)
    deep = await evaluate(send, `(() => {
      const rows = [...document.querySelectorAll('.grid > div')]
      return { rowCount: rows.length, first: rows[0]?.querySelector('code')?.textContent || '' }
    })()`)
    if (deep.rowCount) break
  }

  console.log('all-category rows:', count, '| md5:', sampleMd5)
  console.log('first by strength:', firstByStrength, '| first by name:', firstByName)
  console.log('ldap-category rows:', ldap.rowCount, '| ldap-md5:', ldap.ldapMd5)
  console.log('hash after chip click:', hashAfterChip, '| logo loaded:', logoOk)
  console.log('deep link #ldap-md5 rows:', deep.rowCount, '| first:', deep.first)
  console.log('service worker registered:', pwa.sw, '| manifest status:', pwa.manifest)
  console.log('console errors:', errors.length ? errors : 'none')
  const ok = sampleMd5 === '5f4dcc3b5aa765d61d8327deb882cf99'
    && count > 100
    && firstByStrength === 'argon2id'
    && firstByName === 'adler32'
    && ldap.rowCount === 15
    && ldap.ldapMd5 === '{MD5}X03MO1qnZdYdgyfeuILPmQ=='
    && hashAfterChip === '#cat=ldap'
    && logoOk
    && deep.rowCount === 1
    && deep.first === 'ldap-md5'
    && pwa.sw
    && pwa.manifest === 200
    && errors.length === 0
  console.log(ok ? '\nE2E PASS' : '\nE2E FAIL')
  exitCode = ok ? 0 : 1
  ws.close()
} catch (e) {
  console.error('E2E error:', e.message)
  exitCode = 1
} finally {
  chrome.kill('SIGKILL')
  killPreview()
}
process.exit(exitCode)
