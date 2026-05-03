import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build output is emitted into the Go server's go:embed directory so
// `go build` picks it up automatically. The dev server proxies /api to
// the local daemon at :8080 so frontend devs don't need a separate
// reverse proxy.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
    },
  },
  build: {
    outDir: path.resolve(__dirname, "../internal/api/ui-react/dist"),
    emptyOutDir: true,
    sourcemap: false,
  },
});
