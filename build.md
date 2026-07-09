# mkpasswd — Build Status & Context

## Project Goal

Recreate [mkpasswd.net](https://mkpasswd.net) as a **fully client-side** Astro + Vue 3 + Tailwind CSS v4 application that computes **115 password hash types** entirely in the browser (JavaScript + WebAssembly). No backend, no network requests — everything runs locally in a Web Worker.

**Key UX improvement over original:** Category-first design — chips on top filter the hash list live; one password input drives all 115 results simultaneously.

---

## Status: ✅ COMPLETE & VERIFIED

All tasks finished. The app builds, all 1226 test vectors pass (1205 PHP ground truth + 21 live-site wrapper verification), end-to-end tests pass in headless Chrome, and the production build is 285KB.

### What's Been Implemented

#### 1. **Project Scaffold** ✅
- Astro 7.0.7 + Vue 3.5 + Tailwind CSS v4 (via `@tailwindcss/vite`)
- `package.json` with `dev`, `build`, `preview`, `test`, `test:e2e` scripts
- `.gitignore` (excludes `dist/`, `.astro/`, `node_modules/`, test PNGs)
- `README.md` with full documentation

#### 2. **Cryptographic Algorithms** ✅

**Via hash-wasm (WASM-backed, verified):**
- MD4, MD5, SHA-1, SHA-224/256/384/512, SHA-3 (224/256/384/512)
- RIPEMD-160, Whirlpool
- Adler-32, CRC-32 (reflected), xxHash (32/64/128/3), bcrypt, Argon2i/id

**Hand-ported from php-src (pure JS, verified against PHP vectors):**
- **Tiger** (128/160/192-bit × 3/4 passes, 6 variants) — `src/lib/algos/tiger.js`
  - 4×256 uint64 S-box table transcribed from `php_hash_tiger_tables.h`
  - Tiger1 padding, little-endian 64-bit word output
- **GOST R 34.11-94** (test + CryptoPro S-boxes) — `src/lib/algos/gost.js`
  - Two 4×256 uint32 S-box tables from `php_hash_gost_tables.h`
  - Full LFSR mixing (P, A, AA, C, SHIFT12/16/61)
- **Snefru-2** (256-bit, 8 passes) — `src/lib/algos/snefru.js`
  - 16×256 uint32 S-box table from `php_hash_snefru_tables.h`
- **HAVAL** (15 variants: 3/4/5 passes × 128–256 bits) — `src/lib/algos/haval.js`
  - K2–K5 constants, I2–I5 permutations, tailoring/folding for 128/160/192/224-bit outputs
- **MD2** (RFC 1319) — `src/lib/algos/md2.js`
- **RIPEMD-128/256/320** (160 via hash-wasm) — `src/lib/algos/ripemd.js`
- **SHA-512/224 & SHA-512/256** (custom IV via SHA-512) — `src/lib/algos/sha512t.js`
- **Checksums:** CRC-32/BZIP2, FNV-1/1a (32/64-bit), JOAAT — `src/lib/algos/checksums.js`
- **MurmurHash3** (x86_32, x86_128, x64_128) — `src/lib/algos/murmur3.js`
- **NT hash** (MD4 over UTF-16LE) & **Pre-MySQL-4.1 OLD_PASSWORD()** — `src/lib/algos/misc.js`

#### 3. **crypt() Family** ✅ (`src/lib/crypt/`)

All synchronous (local MD5/SHA-256/SHA-512 primitives to avoid async poisoning):

- **Traditional DES crypt** (13-char, 2-char salt) — `descrypt.js`
  - Bit-level DES with FIPS 46-3 tables, salt perturbation (E-box swap), 25 rounds
- **BSDi extended DES** (`_J9..` prefix, variable rounds) — `descrypt.js`
  - Little-endian 6-bit count decode, password folding for >8 bytes
- **MD5-crypt** (`$1$`) & **APR1** (`$apr1$`) — `md5crypt.js`
  - PHK algorithm: length trickle, 1000 alternating rounds, custom base64 permutation
- **SHA-256-crypt** (`$5$`) & **SHA-512-crypt** (`$6$`) — `shacrypt.js`
  - Drepper spec: digest-A/B, P/S sequences, rounds 1000–999999999 (default 5000)
  - Custom base64 permutations: `(21k, 10+21k, 20+21k) mod 30` (sha256), `(22k, 21+22k, 42+22k) mod 63` (sha512)

#### 4. **Password-Based KDFs** ✅ (`src/lib/kdf.js`)

- **bcrypt** ($2a/$2x/$2y variants, cost 4–15, 72-byte truncation) via hash-wasm
- **Argon2i/id** (memory/time/parallelism tunable) via hash-wasm
- Salt generation & bcrypt base64 encoding/decoding

#### 5. **Wrapper Formats** ✅

Reverse-engineered from live mkpasswd.net (documented in `reference/wrapper-formats.md`):

- **LDAP/OpenLDAP** (15 types): `{MD5}`, `{SMD5}`, `{SHA}`, `{SSHA}`, `{SSHA256/384/512}`, `{CRYPT}` wrappers
  - Salted variants: 8 raw random bytes appended after digest, then base64
- **Apache htpasswd** (6 types): APR1, bcrypt (cost 5), DES crypt, `{SHA}`, sha256/512-crypt
- **IRC daemons**:
  - `ircu-plain` → `$PLAIN$password`
  - `ircu-smd5` → standard md5crypt with internal `$1$`, re-tagged `$SMD5$` (2-char salt)
  - **UnrealIRCd salted digests** (`unreal-md5/sha1/ripemd160`):
    - Double-hash construction: `HASH( rawHASH(password) + salt6_raw )` 
    - Salt: 6 raw bytes, shown as 8 standard-base64 chars
  - `unreal-argon2`/`unreal-argon2id` → argon2id with m=6144, t=2, p=2 (both are aliases)
  - `unreal-bcrypt` → cost 9, `unreal-crypt` → DES
- **Specials:** `plain` (verbatim), `null` (literal `<null>`), `crypt-nthash` (`$3$$` + NT hash)

All verified: 21 wrapper types reproduced offline with extracted salts, exact match to live site.

#### 6. **Registry & Dispatch** ✅

- **`src/lib/registry.js`**: 115 types × metadata (kind, note, bits, salted, params, categories)
  - 22 categories (All, hash(), crypt(), Apache, LDAP, IRC daemons, SHA families, etc.)
  - Category → type mapping (captured from live site's GET `?category=X`)
- **`src/lib/digests.js`**: Canonical PHP `hash()` name → async hex function map
- **`src/lib/hashers.js`**: `compute(type, password, opts)` — pure dispatch (isomorphic, runs in main or worker)
  - Handles digests, crypt family, KDFs, wrappers, specials
  - Salt memo for deterministic re-hashing, param overrides (cost, rounds, memory, etc.)

#### 7. **Web Worker** ✅

- `src/lib/worker.js`: Off-thread hashing with generation-based cancellation
  - Processes batches of jobs, streams results back incrementally
  - Newer generation supersedes in-flight work (debounced password input)

#### 8. **Vue UI** ✅

- **`src/components/HashApp.vue`**: App shell
  - Password input (show/hide, random generator, clear)
  - Category chips (22, with counts, live filter)
  - Search box (filters by type name or description)
  - "Reroll all salts" button (for salted types)
  - Worker client: generation management, result streaming, copy-to-clipboard
- **`src/components/HashRow.vue`**: One hash result row
  - Type label, kind badge (color-coded: digest/crypt/bcrypt/argon2/ldap/apache/irc/checksum/special)
  - Live hash value (or loading skeleton)
  - Copy button with 1.4s feedback animation
  - Options gear (expands to show salt + param sliders for salted/tunable types)
  - Salt display + "Reroll" button, param sliders (bcrypt cost, argon2 memory/time/parallelism, sha-crypt rounds)
- **`src/styles/global.css`**: Tailwind v4 with custom dark-mode palette
  - `--color-ink-*` (neutral), `--color-brand-*` (cyan), `--color-accent-*` (magenta)
  - Radial gradient background, thin custom scrollbars, `animate-rise` keyframe

#### 9. **Testing** ✅

- **PHP ground truth generator** (`tests/gen-vectors.php`):
  - 60 `hash()` algos × 19 inputs (empty, short, long, UTF-8, binary) → `tests/vectors.json`
  - crypt() family (53 vectors: DES, ext-DES, md5/apr1, blowfish $2a/$2x/$2y, sha256/512) + NT hash + OLD_PASSWORD + Argon2 samples → `tests/crypt-vectors.json`
- **Node test runner** (`tests/check.mjs`): 1205 vectors, 0 failures
  - Known divergence: `$2x$` + 8-bit password (hash-wasm produces corrected `$2b$` result, not the 1997 sign-extension bug)
- **Wrapper verification** (`tests/wrapper-verify.mjs`): 21 live-site ground-truth examples, 0 failures
  - Reproduces exact output with same salt (confirms ircu-smd5, unreal double-hash, LDAP/OpenLDAP constructions)
- **Smoke test** (`tests/smoke.mjs`): Quick runtime check of non-crypt types
- **E2E test** (`tests/e2e.mjs`): Headless Chrome via CDP
  - Starts preview server, types "password", waits for worker to compute
  - Verifies 115 rows rendered, `md5("password")` correct in DOM
  - Clicks LDAP category chip, verifies list filters to 15 types, `ldap-md5` value matches live site
  - Screenshots saved to `tests/e2e-screenshot.png` and `tests/e2e-ldap.png`

**Full suite:**
```bash
npm test       # 1205 PHP vectors + 21 wrapper vectors → PASS 1226, FAIL 0
npm run test:e2e  # headless browser → E2E PASS
```

#### 10. **Build & Deploy** ✅

- `npm run build` → static output in `dist/` (285KB, code-split)
- `npm run preview` → serves the build on :4321
- All source files chmod 644 (per user's umask workaround requirement)

---

## What's NOT Done (Future Work)

**Nothing critical — the app is feature-complete.** Possible enhancements:

1. **Empty-password behavior**: Currently returns empty string for all types (matching live site). Could add a "type password to begin" placeholder per row instead of blank output.
2. **Progressive enhancement**: App requires JS; could pre-render static category descriptions or a "requires JS" message for `<noscript>`.
3. **Accessibility audit**: Keyboard nav works (native inputs/buttons), but ARIA labels for dynamically filtered lists and param sliders could be improved.
4. **Dark/light theme toggle**: Skeleton in place (button + localStorage), but only dark theme colors defined. Light mode would need a second palette.
5. **Permalink/share**: Could encode password+salt+params in URL hash for reproducible links (careful: password in URL is a UX/security tradeoff).
6. **Browser compat**: Tested in Chrome 131+; Safari/Firefox untested (hash-wasm WASM should work universally, but bcrypt alphabet edge cases may differ).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  index.astro (entry)                                        │
│    └─> HashApp.vue (shell: password, categories, worker)   │
│          └─> HashRow.vue × 115 (one per visible type)      │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ postMessage({ gen, password, jobs })
                           ▼
                ┌──────────────────────┐
                │   worker.js          │
                │   (Web Worker)       │
                └──────────────────────┘
                           │
                           │ import
                           ▼
                ┌──────────────────────┐
                │   hashers.js         │
                │   compute() dispatch │
                └──────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   digests.js          kdf.js           crypt/*
   (hash-wasm +    (bcrypt, argon2)   (DES, md5, SHA)
    hand-ported)
```

**Key design decisions:**
- **Isomorphic compute layer**: `hashers.js` has no DOM/worker dependencies → runs anywhere, easy to test in Node
- **Worker owns generation tracking**: Main thread fires-and-forgets; worker bails early when superseded
- **Registry drives UI**: `registry.js` is the single source of truth for type metadata, category groupings, and param schemas
- **Salt as hex string in state**: UI stores salt as hex (not raw bytes) so Vue can reactively track it; `hashers.js` converts on demand
- **No TypeScript**: Astro/Vue allow TS, but agents ported from PHP → plain JS for simplicity

---

## Known Issues / Gotchas

1. **Tiger/GOST/Snefru table placeholders**: The agent-written files contain `__TIGER_TABLE_HEX__` / `__GOST_TEST_HEX__` / `__SNEFRU_TABLE_HEX__` placeholders that were replaced during agent execution. If these files show placeholders, the tables weren't written (shouldn't happen in a clean build, but worth noting for context).

2. **bcrypt $2x$ divergence**: PHP's `$2x$` with 8-bit password bytes replicates a 1997 sign-extension bug. `hash-wasm` produces the corrected `$2b$` result. Test suite notes this as "known divergence" and skips 1 case. 7-bit passwords are identical.

3. **Empty password**: Live site returns `""` for every type when password is empty (doesn't hash at all). This is replicated exactly, but could confuse users expecting a hash of the empty string.

4. **Async digests**: `hash-wasm` functions return Promises (WASM init). This makes the entire `compute()` function async. The crypt family uses **sync** local MD5/SHA-256/SHA-512 (reimplemented in pure JS) to avoid poisoning the call chain.

5. **Argon2 params**: `unreal-argon2` and `unreal-argon2id` are **aliases** — both emit `$argon2id$` with m=6144, t=2, p=2. The UI shows sliders for both, but they produce identical output for the same password+salt.

---

## File Manifest

### Source (`src/`)
- `pages/index.astro` — entry page, mounts `<HashApp client:load />`
- `components/HashApp.vue` — password input, category chips, worker client, row list
- `components/HashRow.vue` — one hash row (label, value, copy, salt, param sliders)
- `styles/global.css` — Tailwind v4 + custom palette + animations
- `lib/registry.js` — 115 types, 22 categories, metadata (kind, params, categories)
- `lib/hashers.js` — `compute(type, password, opts)` dispatch (pure, isomorphic)
- `lib/digests.js` — PHP `hash()` name → async hex function (WASM + hand-ported)
- `lib/kdf.js` — bcrypt/argon2 wrappers, salt generation, bcrypt base64
- `lib/b64.js` — base64 encode/decode, hex↔bytes, concat helpers
- `lib/worker.js` — Web Worker: generation-based batch processor
- `lib/algos/` — tiger, gost, snefru, haval, md2, ripemd, sha512t, checksums, murmur3, misc (nthash, premysql41)
- `lib/crypt/` — descrypt (DES, ext-DES), md5crypt (md5/$apr1$), shacrypt (sha256/512)

### Tests (`tests/`)
- `gen-vectors.php` — PHP ground truth generator (requires php, openssl, python3)
- `vectors.json` — 60 algos × 19 inputs (1140 digest cases)
- `crypt-vectors.json` — 53 crypt cases + specials + argon2
- `check.mjs` — Node test runner (1205 vectors)
- `wrapper-verify.mjs` — 21 live-site wrapper ground truth checks
- `smoke.mjs` — Quick runtime check
- `e2e.mjs` — Headless Chrome via CDP (types password, reads DOM, screenshots)
- `e2e-screenshot.png`, `e2e-ldap.png` — E2E screenshots (gitignored)

### Reference (`reference/`)
- `MKPasswd - Generate password hashes online.html` — original site snapshot
- `password_q_qc.png` — original site logo
- `category-map.json` — category → type mapping (captured from live site)
- `wrapper-formats.md` — reverse-engineered wrapper specs (42 types)
- `wrapper-probes.json` — raw live-site probe data (7 samples × 42 types)

### Config
- `package.json` — Astro + Vue + Tailwind + hash-wasm deps, npm scripts
- `astro.config.mjs` — Astro 7 + Vue integration + Tailwind vite plugin
- `.gitignore` — node_modules, dist, .astro, test PNGs
- `README.md` — user-facing docs
- `build.md` — this file (project status / handoff doc)

---

## How to Continue / Extend

### To add a new hash type:
1. Implement the algorithm in `src/lib/algos/` or wire it via hash-wasm in `src/lib/digests.js`
2. Add a test case to `tests/gen-vectors.php` (for PHP-backed types) or manually to `tests/check.mjs`
3. Add dispatch case to `src/lib/hashers.js` `compute()` switch
4. Add metadata to `src/lib/registry.js` `TYPES` object
5. Add to appropriate category in `registry.js` `categoryMap`
6. Run `npm test` to verify

### To tweak the UI:
- Colors: edit `src/styles/global.css` `@theme` block
- Category list: edit `CATEGORIES` in `src/lib/registry.js`
- Param ranges: edit `P.*` descriptors in `src/lib/registry.js`
- Row layout: edit `src/components/HashRow.vue`

### To debug wrapper formats:
- Live-site probe: `curl -s "https://mkpasswd.net/index.php" --data-urlencode "data=password" --data-urlencode "type=<TYPE>" --data-urlencode "action=Hash" | grep -oE 'readonly[^>]*value="[^"]*"'`
- Compare against `reference/wrapper-formats.md` spec
- Recompute offline in `tests/wrapper-verify.mjs` to isolate salt/construction issues

---

## Agent Handoff Notes

This was a **parallel multi-agent build**:
- **Agent 1** (tiger/gost/snefru): Ported 3 digest families from php-src, transcribed S-box tables → 190 passing vectors
- **Agent 2** (haval/md2/ripemd): Ported 3 more families → 380 passing vectors
- **Agent 3** (crypt family): DES/ext-DES, md5crypt/apr1, sha256/512-crypt with local sync primitives → 132 passing vectors
- **Agent 4** (wrapper research): Reverse-engineered 42 wrapper formats from live site, verified all offline → documented in `reference/wrapper-formats.md`

All agents completed successfully. All files chmod 644 (user's environment has a umask quirk). Full test suite passes (1226 vectors). E2E test passes (115 rows, category filter works, zero console errors). Build is 285KB. **The project is DONE and ready to ship.**

To verify the build yourself:
```bash
npm install
npm test          # should show PASS 1226, FAIL 0
npm run build     # should complete with no errors
npm run preview   # serves on :4321
npm run test:e2e  # headless Chrome test (requires chromium/google-chrome)
```
