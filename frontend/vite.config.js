import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],

  // Tauri expects a fixed port in dev mode
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },

  // Tauri: use relative paths in production build
  base: process.env.TAURI_ENV_DEBUG ? '/' : process.env.TAURI ? './' : '/',

  build: {
    // Tauri uses Chromium — no need for polyfills
    target: process.env.TAURI ? ['es2021', 'chrome105'] : 'modules',
    // Don't minify for Tauri debug builds
    minify: process.env.TAURI_ENV_DEBUG ? false : 'esbuild',
    sourcemap: !!process.env.TAURI_ENV_DEBUG,
  },
})
