import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    lib: {
      entry: 'main.js',
      formats: ['es'],
      fileName: () => 'main.js'
    }
  }
}) 