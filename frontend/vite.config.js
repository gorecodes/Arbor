import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  server: {
    proxy: {
      '/api': {
        target: 'https://localhost:8443',
        changeOrigin: true,
        secure: false,
      },
      '/ws': {
        target: 'wss://localhost:8443',
        ws: true,
        secure: false,
      }
    }
  },
  build: {
    outDir: 'dist',
  }
})
