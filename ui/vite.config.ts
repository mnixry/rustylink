import path from "node:path"
import babel from "@rolldown/plugin-babel"
import tailwindcss from "@tailwindcss/vite"
import react, { reactCompilerPreset } from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    // React Compiler (React 19) via the rolldown babel preset.
    babel({ presets: [reactCompilerPreset()] }),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    proxy: {
      // Connect-RPC is served by the daemon under /api; proxy it in dev so the
      // browser talks same-origin (no CORS). The daemon embeds the SPA in prod.
      "/api": {
        target: "http://127.0.0.1:7878",
        changeOrigin: true,
      },
    },
  },
})
