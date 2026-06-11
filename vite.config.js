// vite.config.js – minimal config with API proxy for backend
import { defineConfig } from 'vite';

export default defineConfig({
  root: 'frontend',
  base: '/',
  server: {
    port: 3100,
    open: false,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://localhost:4001',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    outDir: '../dist',
    emptyOutDir: true,
  },
});
