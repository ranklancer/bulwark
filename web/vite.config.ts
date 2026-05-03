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
    // Don't empty the outDir — that wipes the committed placeholder
    // index.html + .gitignore. Stale hashed-asset files accumulate
    // locally, but assets/ is gitignored so they don't reach commits;
    // CI does a fresh checkout each run so accumulation is bounded
    // there too. The prebuild npm script clears assets/ before each
    // build to keep local dist/ tidy.
    emptyOutDir: false,
    sourcemap: false,
  },
});
