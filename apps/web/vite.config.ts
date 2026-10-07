import { fileURLToPath, URL } from 'node:url'

import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  // The controller writes a fresh per-response nonce over this placeholder
  // and allows it in the CSP's style-src (crates/fleet-controller/src/browser.rs),
  // so runtime-injected styles (CodeMirror's theme) apply without 'unsafe-inline'.
  // Vite also emits <meta property="csp-nonce">, which cspNonce() reads.
  html: {
    cspNonce: '__FLEET_CSP_NONCE__',
  },
  build: {
    outDir: 'dist',
  },
})
