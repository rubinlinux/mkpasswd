<script setup>
import { ref, reactive, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import HashRow from './HashRow.vue'
import { CATEGORIES, typesForCategory, typeMeta } from '../lib/registry.js'

const logoUrl = `${import.meta.env.BASE_URL.replace(/\/$/, '')}/favicon.svg`

const password = ref('')
const reveal = ref(false)
const category = ref('all')
const query = ref('')
const theme = ref('dark')

const results = reactive({}) // type -> { value, salt, saltBytes, ms, error }
const pending = reactive({}) // type -> bool
const paramState = reactive({}) // type -> { key: value }
const saltMemo = reactive({}) // type -> { salt, saltBytes }
const expanded = reactive({}) // type -> bool
const copied = ref(null)
const shared = ref(null)
const computing = ref(false)

let worker = null
let gen = 0
let debounceTimer = null
let copyTimer = null
let shareTimer = null

const categories = CATEGORIES.map((c) => ({
  ...c,
  count: typesForCategory(c.id).length,
}))

// --- URL #hash <-> filter state (shareable links) ---
// #cat=<category>&q=<search> for filters; #<type-name> (or #type=<name>) pins
// exactly that one type. Bare #<category> also works; where a bare token is
// both a category and a type ("crypt", "sha1"), the category wins.
const categoryIds = new Set(CATEGORIES.map((c) => c.id))
const typeNames = new Set(typesForCategory('all'))
const pinnedType = ref('')

function applyHash() {
  const raw = location.hash.slice(1)
  let cat = 'all'
  let q = ''
  let pin = ''
  if (raw.includes('=')) {
    const params = new URLSearchParams(raw)
    const c = params.get('cat')
    if (c && categoryIds.has(c)) cat = c
    q = (params.get('q') ?? '').trim()
    const t = (params.get('type') ?? '').trim()
    if (typeNames.has(t)) pin = t
  } else if (raw) {
    const token = decodeURIComponent(raw)
    if (categoryIds.has(token)) cat = token
    else if (typeNames.has(token)) pin = token
  }
  category.value = cat
  query.value = q
  pinnedType.value = pin
}

watch([category, query, pinnedType], () => {
  let h = ''
  if (pinnedType.value) {
    h = '#' + pinnedType.value
  } else {
    const params = new URLSearchParams()
    if (category.value !== 'all') params.set('cat', category.value)
    const q = query.value.trim()
    if (q) params.set('q', q)
    const s = params.toString()
    h = s ? '#' + s : ''
  }
  // replaceState: no history spam, and it never fires hashchange -> no loop
  history.replaceState(null, '', location.pathname + location.search + h)
})

const activeBlurb = computed(() => categories.find((c) => c.id === category.value)?.blurb ?? '')

const visibleTypes = computed(() => {
  if (pinnedType.value) return [pinnedType.value]
  const base = typesForCategory(category.value)
  const q = query.value.trim().toLowerCase()
  if (!q) return base
  return base.filter((t) => t.toLowerCase().includes(q) || typeMeta(t).note.toLowerCase().includes(q))
})

const rows = computed(() => visibleTypes.value.map((t) => ({ type: t, meta: typeMeta(t) })))
const saltedCount = computed(() => visibleTypes.value.filter((t) => typeMeta(t).salted).length)

function paramsFor(type) {
  const meta = typeMeta(type)
  if (!meta.params.length) return undefined
  const cur = paramState[type] ?? {}
  const out = {}
  for (const p of meta.params) out[p.key] = cur[p.key] ?? p.default
  return out
}

function schedule() {
  clearTimeout(debounceTimer)
  debounceTimer = setTimeout(runCompute, 180)
}

function runCompute() {
  if (!worker) return
  const types = visibleTypes.value
  if (password.value === '') {
    gen++
    for (const k of Object.keys(results)) delete results[k]
    for (const k of Object.keys(pending)) delete pending[k]
    computing.value = false
    return
  }
  gen++
  computing.value = true
  for (const t of types) if (!results[t]) pending[t] = true
  const jobs = types.map((t) => ({
    type: t,
    params: paramsFor(t),
    salt: saltMemo[t]?.salt,
    saltBytes: saltMemo[t]?.saltBytes,
  }))
  worker.postMessage({ kind: 'compute', gen, password: password.value, jobs })
}

function onWorkerMessage(e) {
  const msg = e.data
  if (msg.gen !== gen) return
  if (msg.kind === 'done') { computing.value = false; return }
  if (msg.kind !== 'result') return
  const { type, value, salt, saltBytes, ms, error } = msg
  results[type] = { value, salt, saltBytes, ms, error }
  pending[type] = false
  if ((salt || saltBytes) && !saltMemo[type]) saltMemo[type] = { salt, saltBytes }
}

async function copy(type) {
  const r = results[type]
  if (!r || r.value === undefined || r.value === '') return
  try {
    await navigator.clipboard.writeText(r.value)
    copied.value = type
    clearTimeout(copyTimer)
    copyTimer = setTimeout(() => (copied.value = null), 1400)
  } catch { /* clipboard blocked */ }
}

async function share(type) {
  const url = `${location.origin}${location.pathname}${location.search}#${type}`
  try {
    await navigator.clipboard.writeText(url)
    shared.value = type
    clearTimeout(shareTimer)
    shareTimer = setTimeout(() => (shared.value = null), 1400)
  } catch { /* clipboard blocked */ }
}

function reroll(type) {
  delete saltMemo[type]
  delete results[type]
  pending[type] = true
  runCompute()
}

function rerollAll() {
  for (const k of Object.keys(saltMemo)) delete saltMemo[k]
  runCompute()
}

function toggle(type) { expanded[type] = !expanded[type] }

function setParam({ type, key, value }) {
  if (!paramState[type]) paramState[type] = {}
  paramState[type][key] = value
  delete results[type]
  delete saltMemo[type]
  pending[type] = true
  schedule()
}

function randomPassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+'
  const bytes = new Uint8Array(20)
  crypto.getRandomValues(bytes)
  password.value = Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
  reveal.value = true
}

function clearAll() {
  password.value = ''
  reveal.value = false
}

function pickCategory(id) {
  category.value = id
  query.value = ''
  pinnedType.value = ''
}

function toggleTheme() {
  theme.value = theme.value === 'dark' ? 'light' : 'dark'
  document.documentElement.setAttribute('data-theme', theme.value)
  document.documentElement.style.colorScheme = theme.value
  try { localStorage.setItem('mkpasswd-theme', theme.value) } catch {}
}

watch([password, category, query], schedule)
watch(visibleTypes, schedule)

onMounted(() => {
  try {
    const saved = localStorage.getItem('mkpasswd-theme')
    if (saved) { theme.value = saved; document.documentElement.setAttribute('data-theme', saved); document.documentElement.style.colorScheme = saved }
  } catch {}
  worker = new Worker(new URL('../lib/worker.js', import.meta.url), { type: 'module' })
  worker.onmessage = onWorkerMessage
  applyHash()
  window.addEventListener('hashchange', applyHash)
})

onBeforeUnmount(() => {
  worker?.terminate()
  clearTimeout(debounceTimer)
  clearTimeout(copyTimer)
  clearTimeout(shareTimer)
  window.removeEventListener('hashchange', applyHash)
})
</script>

<template>
  <div class="mx-auto flex min-h-screen max-w-4xl flex-col gap-6 px-4 py-8 sm:px-6 sm:py-12">
    <!-- Header -->
    <header class="flex items-start justify-between gap-4">
      <div>
        <div class="flex items-center gap-2.5">
          <img :src="logoUrl" alt="" class="h-9 w-9" aria-hidden="true" />
          <h1 class="text-2xl font-bold tracking-tight text-ink-50">mkpasswd</h1>
        </div>
        <p class="mt-1.5 max-w-lg text-sm text-ink-400">
          Generate 100+ kinds of password hashes. Everything runs locally with WebAssembly —
          <span class="text-brand-300">your password never leaves this page.</span>
        </p>
      </div>
      <button
        class="shrink-0 rounded-lg border border-ink-800 bg-ink-900/60 p-2 text-ink-400 transition hover:text-ink-100"
        title="Toggle theme"
        @click="toggleTheme"
      >
        <svg v-if="theme === 'dark'" viewBox="0 0 24 24" class="h-5 w-5" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19" />
        </svg>
        <svg v-else viewBox="0 0 24 24" class="h-5 w-5" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
        </svg>
      </button>
    </header>

    <!-- Password input -->
    <div class="rounded-2xl border border-ink-800 bg-ink-900/50 p-1.5 shadow-xl shadow-black/20 backdrop-blur">
      <div class="flex items-center gap-1.5">
        <div class="pl-3 text-ink-500">
          <svg viewBox="0 0 24 24" class="h-5 w-5" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" />
          </svg>
        </div>
        <input
          :type="reveal ? 'text' : 'password'"
          v-model="password"
          placeholder="Type a password to hash…"
          autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"
          class="min-w-0 flex-1 bg-transparent px-2 py-3 font-mono text-base text-ink-50 placeholder:text-ink-600 focus:outline-none"
        />
        <button class="rounded-lg p-2 text-ink-500 transition hover:text-ink-200" :title="reveal ? 'Hide' : 'Show'" @click="reveal = !reveal">
          <svg v-if="!reveal" viewBox="0 0 24 24" class="h-5 w-5" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" /><circle cx="12" cy="12" r="3" />
          </svg>
          <svg v-else viewBox="0 0 24 24" class="h-5 w-5" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M3 3l18 18M10.6 10.6a3 3 0 0 0 4.2 4.2M9.9 5.2A9.5 9.5 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4M6.3 6.3A17 17 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 2.1-.2" />
          </svg>
        </button>
        <button class="rounded-lg p-2 text-ink-500 transition hover:text-ink-200" title="Generate random password" @click="randomPassword">
          <svg viewBox="0 0 24 24" class="h-5 w-5" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="18" height="18" rx="3" /><circle cx="8" cy="8" r="1.2" fill="currentColor" /><circle cx="16" cy="16" r="1.2" fill="currentColor" /><circle cx="16" cy="8" r="1.2" fill="currentColor" /><circle cx="8" cy="16" r="1.2" fill="currentColor" />
          </svg>
        </button>
        <button v-if="password" class="mr-1 rounded-lg p-2 text-ink-500 transition hover:text-ink-200" title="Clear" @click="clearAll">
          <svg viewBox="0 0 24 24" class="h-5 w-5" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12" /></svg>
        </button>
      </div>
    </div>

    <!-- Category chips -->
    <div class="flex flex-wrap gap-1.5">
      <button
        v-for="c in categories" :key="c.id"
        class="rounded-full border px-3 py-1.5 text-xs font-medium transition"
        :class="category === c.id
          ? 'border-brand-500/60 bg-brand-500/15 text-brand-200'
          : 'border-ink-800 bg-ink-900/40 text-ink-400 hover:border-ink-700 hover:text-ink-200'"
        @click="pickCategory(c.id)"
      >
        {{ c.label }}
        <span class="ml-1 font-mono text-[10px] opacity-60">{{ c.count }}</span>
      </button>
    </div>

    <!-- Toolbar -->
    <div class="flex flex-wrap items-center gap-3">
      <div class="relative min-w-0 flex-1">
        <svg viewBox="0 0 24 24" class="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-600" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" />
        </svg>
        <input
          v-model="query" type="text" placeholder="Filter algorithms…"
          class="w-full rounded-lg border border-ink-800 bg-ink-900/40 py-2 pl-9 pr-3 text-sm text-ink-100 placeholder:text-ink-600 focus:border-brand-500/50 focus:outline-none"
          @input="pinnedType = ''"
        />
      </div>
      <button
        v-if="saltedCount > 0 && password"
        class="flex items-center gap-1.5 rounded-lg border border-ink-800 bg-ink-900/40 px-3 py-2 text-xs font-medium text-ink-400 transition hover:text-ink-100"
        title="Reroll all salts"
        @click="rerollAll"
      >
        <svg viewBox="0 0 24 24" class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 0 1 15-6.7L21 8M21 3v5h-5M21 12a9 9 0 0 1-15 6.7L3 16M3 21v-5h5" /></svg>
        Reroll salts
      </button>
      <button
        v-if="pinnedType"
        class="flex items-center gap-1.5 rounded-full border border-brand-500/60 bg-brand-500/15 px-3 py-1.5 text-xs font-medium text-brand-200 transition hover:bg-brand-500/25"
        title="Show all types again"
        @click="pickCategory('all')"
      >
        <span class="font-mono">{{ pinnedType }}</span>
        <svg viewBox="0 0 24 24" class="h-3.5 w-3.5" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12" /></svg>
      </button>
      <span class="shrink-0 font-mono text-xs text-ink-600">
        <span v-if="computing" class="text-brand-400">computing…</span>
        <span v-else>{{ rows.length }} {{ rows.length === 1 ? 'type' : 'types' }}</span>
      </span>
    </div>
    <p class="-mt-3 text-xs text-ink-600">{{ activeBlurb }}</p>

    <!-- Results -->
    <div class="flex-1">
      <div v-if="password === ''" class="flex flex-col items-center justify-center rounded-2xl border border-dashed border-ink-800 py-20 text-center">
        <svg viewBox="0 0 24 24" class="h-10 w-10 text-ink-700" fill="none" stroke="currentColor" stroke-width="1.5">
          <rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" />
        </svg>
        <p class="mt-4 text-sm text-ink-500">Enter a password above to generate hashes.</p>
        <button class="mt-3 text-xs font-medium text-brand-400 hover:text-brand-300" @click="randomPassword">or generate a random one</button>
      </div>
      <div v-else-if="rows.length === 0" class="rounded-2xl border border-dashed border-ink-800 py-16 text-center text-sm text-ink-500">
        No algorithms match “{{ query }}”.
      </div>
      <div v-else class="grid gap-2.5">
        <HashRow
          v-for="row in rows" :key="row.type"
          :type="row.type" :meta="row.meta"
          :result="results[row.type]"
          :params="paramState[row.type] || {}"
          :expanded="!!expanded[row.type]"
          :copied="copied === row.type"
          :shared="shared === row.type"
          @copy="copy" @reroll="reroll" @toggle="toggle" @param="setParam" @share="share"
        />
      </div>
    </div>

    <!-- Footer -->
    <footer class="mt-4 border-t border-ink-800/60 pt-6 text-center text-xs text-ink-600">
      <p>
        All hashing happens in your browser via JavaScript &amp; WebAssembly. No network requests, no logging.
      </p>
      <p class="mt-1">A modern reimagining of mkpasswd.net — {{ categories.find(c => c.id === 'all')?.count }} hash types, zero server round-trips.</p>
    </footer>
  </div>
</template>
