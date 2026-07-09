import { defineConfig } from 'astro/config'
import vue from '@astrojs/vue'
import tailwindcss from '@tailwindcss/vite'
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'

// Emits dist/sw.js after the build: precaches every built asset (URLs relative
// to the SW scope, so it works under any base path) with a content-hashed cache
// name — each deploy installs a fresh cache and drops the old one on activate.
function serviceWorker() {
  return {
    name: 'service-worker',
    hooks: {
      'astro:build:done': ({ dir }) => {
        const root = fileURLToPath(dir)
        const files = readdirSync(root, { recursive: true, withFileTypes: true })
          .filter((e) => e.isFile())
          .map((e) => relative(root, join(e.parentPath ?? e.path, e.name)).split(sep).join('/'))
          .filter((f) => f !== 'sw.js' && !f.endsWith('.html'))
          .sort()
        const hash = createHash('sha256')
        for (const f of [...files, 'index.html']) hash.update(readFileSync(join(root, f)))
        const cache = `mkpasswd-${hash.digest('hex').slice(0, 12)}`
        const assets = ['./', ...files.map((f) => './' + f)]
        writeFileSync(join(root, 'sw.js'), `// generated at build time — see astro.config.mjs
const CACHE = ${JSON.stringify(cache)}
const ASSETS = ${JSON.stringify(assets)}

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()))
})

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()))
})

// ignoreVary: dev/preview servers send "Vary: Origin", which would make
// precached entries unmatchable for CORS-mode module imports
const OPTS = { ignoreVary: true }

self.addEventListener('fetch', (e) => {
  const req = e.request
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin) return
  if (req.mode === 'navigate') {
    // network-first for the page itself so new deploys show up promptly
    e.respondWith(fetch(req).then((res) => {
      const copy = res.clone()
      caches.open(CACHE).then((c) => c.put('./', copy))
      return res
    }).catch(() => caches.match('./', OPTS)))
  } else {
    // cache-first for hashed static assets
    e.respondWith(caches.match(req, OPTS).then((hit) => hit || fetch(req).then((res) => {
      if (res.ok) {
        const copy = res.clone()
        caches.open(CACHE).then((c) => c.put(req, copy))
      }
      return res
    })))
  }
})
`)
        console.log(`[service-worker] dist/sw.js: ${assets.length} assets precached as ${cache}`)
      },
    },
  }
}

export default defineConfig({
  site: 'https://rubinlinux.github.io',
  base: '/mkpasswd',
  integrations: [vue(), serviceWorker()],
  vite: {
    plugins: [tailwindcss()],
  },
})
