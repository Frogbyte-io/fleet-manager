import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
  },
  test: {
    environment: 'jsdom',
    // Specs mount the full router and lazy pages; the first mount in a file is
    // slow, and under host load (several verify runs at once) the 5 s default
    // gives false failures. A real hang still fails, just later.
    testTimeout: 20_000,
    hookTimeout: 30_000,
    // Keep slow tests visible in the reporter even though they no longer fail.
    slowTestThreshold: 3_000,
  },
})
