// Headless end-to-end check via the Chrome DevTools Protocol (no external deps).
// Starts the preview server if :4321 isn't already serving, launches chrome,
// types a password, waits for the worker to compute, then reads back rendered
// rows + a known hash and screenshots.
import { spawn } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// must match the `base` in astro.config.mjs (site is served under a subpath)
const BASE = process.env.BASE_URL || 'http://localhost:4321/mkpasswd'
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

  await send('Page.navigate', { url: BASE })
  await sleep(1500) // hydrate + worker init

  // type a password into the input
  await evaluate(send, `(() => {
    const el = document.querySelector('input[type=password], input[type=text]')
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set
    setter.call(el, 'password')
    el.dispatchEvent(new Event('input', { bubbles: true }))
    return true
  })()`)

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

  const shot = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true })
  writeFileSync('tests/e2e-ldap.png', Buffer.from(shot.data, 'base64'))

  // back to All for the full-page screenshot
  await evaluate(send, `[...document.querySelectorAll('button')].find(b => b.textContent.trim().startsWith('All')).click()`)
  await sleep(1500)
  const shot2 = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true })
  writeFileSync('tests/e2e-screenshot.png', Buffer.from(shot2.data, 'base64'))

  console.log('all-category rows:', count, '| md5:', sampleMd5)
  console.log('ldap-category rows:', ldap.rowCount, '| ldap-md5:', ldap.ldapMd5)
  console.log('console errors:', errors.length ? errors : 'none')
  const ok = sampleMd5 === '5f4dcc3b5aa765d61d8327deb882cf99'
    && count > 100
    && ldap.rowCount === 15
    && ldap.ldapMd5 === '{MD5}X03MO1qnZdYdgyfeuILPmQ=='
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
