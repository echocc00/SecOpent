import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    port: 5173,
    proxy: {
      // Frontend calls /api/*; the rewrite strips the prefix so it maps to the
      // FastAPI routes mounted at the backend root (e.g. /api/projects -> /projects).
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
      "/ws": { target: "ws://localhost:8000", ws: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    // Monaco (lazy-loaded in the CaseStudio chunk) is intentionally large.
    chunkSizeWarningLimit: 3000,
  },
});
