import { defineConfig } from 'astro/config'
import vue from '@astrojs/vue'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  site: 'https://rubinlinux.github.io',
  base: '/mkpasswd',
  integrations: [vue()],
  vite: {
    plugins: [tailwindcss()],
  },
})
