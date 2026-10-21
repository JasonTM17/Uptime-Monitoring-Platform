import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Same-origin API in dev: the Go server owns :8080; the proxy keeps
// cookies/CSRF same-origin so the client never crosses origins.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8080",
        changeOrigin: false,
      },
    },
  },
  build: {
    sourcemap: true,
    target: "es2022",
  },
});
