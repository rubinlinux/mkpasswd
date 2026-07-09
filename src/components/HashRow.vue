<script setup>
import { computed } from 'vue'
import { strengthTier } from '../lib/registry.js'

const props = defineProps({
  type: { type: String, required: true },
  meta: { type: Object, required: true },
  result: { type: Object, default: null },
  params: { type: Object, default: () => ({}) },
  expanded: { type: Boolean, default: false },
  copied: { type: Boolean, default: false },
  shared: { type: Boolean, default: false },
})
const emit = defineEmits(['copy', 'reroll', 'toggle', 'param', 'share'])

const KIND_STYLE = {
  checksum: 'text-ink-300 bg-ink-800 ring-ink-700',
  digest: 'text-brand-300 bg-brand-500/10 ring-brand-500/30',
  crypt: 'text-amber-300 bg-amber-500/10 ring-amber-500/30',
  bcrypt: 'text-orange-300 bg-orange-500/10 ring-orange-500/30',
  argon2: 'text-accent-400 bg-accent-500/10 ring-accent-500/30',
  ldap: 'text-sky-300 bg-sky-500/10 ring-sky-500/30',
  apache: 'text-rose-300 bg-rose-500/10 ring-rose-500/30',
  irc: 'text-emerald-300 bg-emerald-500/10 ring-emerald-500/30',
  special: 'text-ink-300 bg-ink-800 ring-ink-700',
}

const TIER_STYLE = {
  strong: 'text-emerald-300 bg-emerald-500/10 ring-emerald-500/30',
  good: 'text-teal-300 bg-teal-500/10 ring-teal-500/30',
  fair: 'text-amber-300 bg-amber-500/10 ring-amber-500/30',
  weak: 'text-orange-300 bg-orange-500/10 ring-orange-500/30',
  none: 'text-rose-300 bg-rose-500/10 ring-rose-500/30',
}

const badgeClass = computed(() => KIND_STYLE[props.meta.kind] ?? KIND_STYLE.digest)
const tier = computed(() => strengthTier(props.meta.strength ?? 0))
const tierClass = computed(() => TIER_STYLE[tier.value])
const hasValue = computed(() => props.result && props.result.value !== undefined && !props.result.error)
const isEmptyString = computed(() => hasValue.value && props.result.value === '')
const configurable = computed(() => props.meta.salted || props.meta.params.length > 0)
</script>

<template>
  <div
    class="group rounded-xl border border-ink-800/80 bg-ink-900/40 px-4 py-3 backdrop-blur-sm transition-colors hover:border-ink-700"
    :class="{ 'ring-1 ring-brand-500/40': copied }"
  >
    <div class="flex items-center gap-3">
      <code class="shrink-0 font-mono text-sm font-medium text-ink-100">{{ type }}</code>
      <span
        class="shrink-0 rounded-md px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide ring-1 ring-inset"
        :class="badgeClass"
      >{{ meta.kind }}</span>
      <span v-if="meta.bits" class="shrink-0 font-mono text-[10px] text-ink-500">{{ meta.bits }}-bit</span>

      <div class="ml-auto flex shrink-0 items-center gap-1">
        <span
          class="mr-1 rounded-md px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide ring-1 ring-inset"
          :class="tierClass"
          :title="`Resistance to offline password cracking: ${meta.strength ?? 0}/100`"
        >{{ tier }}</span>
        <span v-if="result && result.ms > 40" class="mr-1 font-mono text-[10px] text-ink-600">{{ result.ms }}ms</span>
        <button
          v-if="configurable"
          class="rounded-md p-1.5 text-ink-500 transition hover:bg-ink-800 hover:text-ink-200"
          :class="{ 'text-brand-400': expanded }"
          title="Options"
          @click="emit('toggle', type)"
        >
          <svg viewBox="0 0 24 24" class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="3" /><path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6l2.1 2.1m0-12.8l-2.1 2.1M7.7 16.3l-2.1 2.1" />
          </svg>
        </button>
        <button
          class="rounded-md p-1.5 text-ink-500 transition hover:bg-ink-800 hover:text-ink-200"
          title="Copy link to this type"
          @click="emit('share', type)"
        >
          <svg v-if="!shared" viewBox="0 0 24 24" class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7" />
          </svg>
          <svg v-else viewBox="0 0 24 24" class="h-4 w-4 text-brand-400" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M5 13l4 4L19 7" />
          </svg>
        </button>
        <button
          class="flex items-center gap-1 rounded-md px-2 py-1.5 text-xs font-medium text-ink-400 transition hover:bg-ink-800 hover:text-ink-100 disabled:opacity-30"
          :disabled="!hasValue || isEmptyString"
          title="Copy"
          @click="emit('copy', type)"
        >
          <svg v-if="!copied" viewBox="0 0 24 24" class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" />
          </svg>
          <svg v-else viewBox="0 0 24 24" class="h-4 w-4 text-brand-400" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M5 13l4 4L19 7" />
          </svg>
          <span>{{ copied ? 'Copied' : 'Copy' }}</span>
        </button>
      </div>
    </div>

    <div class="mt-2">
      <p
        v-if="hasValue && !isEmptyString"
        class="font-mono text-[13px] leading-relaxed break-all text-brand-200 selection:bg-brand-500/30"
      >{{ result.value }}</p>
      <p v-else-if="isEmptyString" class="font-mono text-[13px] italic text-ink-600">(empty output)</p>
      <p v-else-if="result && result.error" class="font-mono text-[12px] text-rose-400/90">⚠ {{ result.error }}</p>
      <div v-else class="h-4 w-2/3 animate-pulse rounded bg-ink-800/70"></div>
    </div>

    <p v-if="meta.note" class="mt-1 text-[11px] text-ink-600">{{ meta.note }}</p>

    <div v-if="expanded && configurable" class="mt-3 space-y-3 rounded-lg bg-ink-950/50 p-3 ring-1 ring-ink-800 animate-rise">
      <div v-if="meta.salted && result && (result.salt || result.saltBytes)" class="flex items-center gap-2">
        <span class="w-16 shrink-0 text-[11px] uppercase tracking-wide text-ink-500">Salt</span>
        <code class="flex-1 truncate rounded bg-ink-900 px-2 py-1 font-mono text-[11px] text-ink-300">{{ result.salt || '(random)' }}</code>
        <button
          class="rounded-md px-2 py-1 text-[11px] font-medium text-brand-400 ring-1 ring-brand-500/30 transition hover:bg-brand-500/10"
          @click="emit('reroll', type)"
        >Reroll</button>
      </div>
      <div v-for="p in meta.params" :key="p.key" class="flex items-center gap-3">
        <span class="w-16 shrink-0 text-[11px] uppercase tracking-wide text-ink-500">{{ p.label }}</span>
        <input
          type="range" :min="p.min" :max="p.max" :step="p.step"
          :value="params[p.key] ?? p.default"
          class="h-1.5 flex-1 cursor-pointer appearance-none rounded-full bg-ink-700 accent-brand-500"
          @input="emit('param', { type, key: p.key, value: Number($event.target.value) })"
        />
        <code class="w-20 shrink-0 text-right font-mono text-[11px] text-ink-300">{{ params[p.key] ?? p.default }}</code>
      </div>
    </div>
  </div>
</template>
