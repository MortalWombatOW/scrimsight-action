import { defineConfig } from 'vite'
import { builtinModules } from 'module'

export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'node20',
    lib: {
      entry: 'main.js',
      formats: ['es'],
      fileName: () => 'main.js'
    },
    rollupOptions: {
      external: [
        ...builtinModules,
        /^node:/
      ],
    }
  },
  platform: 'node'
}) 