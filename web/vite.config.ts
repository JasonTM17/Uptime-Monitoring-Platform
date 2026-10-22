import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Same-origin API in dev: the Go server owns :8080; the proxy keeps
// cookies/CSRF same-origin so the client never crosses origins.
// The client calls /api/* as an edge convention; the app itself serves
// unprefixed routes (OpenAPI server http://127.0.0.1:8080), so the edge
// MUST strip /api before forwarding — same rule a production ingress
// (or static host) applies when colocating SPA + API on one origin.
// E2E_API_TARGET overrides the upstream — the acceptance harness
// (scripts/accept-local.mjs) points the dev server at the composed
// testapp on :18080; local dev keeps the default.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.E2E_API_TARGET ?? "http://localhost:8080",
        changeOrigin: false,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
  build: {
    sourcemap: true,
    target: "es2022",
  },
});
