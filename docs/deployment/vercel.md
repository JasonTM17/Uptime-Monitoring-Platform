# Vercel Hobby frontend — hosted deployment notes

Static Vite build (`web/`) on Hobby: `npm run build` → `dist/`.
`web/vercel.json` rewrites `/api/:path*` to the Render origin — the
browser sees one origin, so session cookies and CSRF stay simple.

## Contract

- **Same-origin API** — rewrite destination is `https://<render-app>
  .onrender.com/api/:path*`; `UPTIME_RENDER_HOST` is substituted at
  provision time. Cross-origin cookies are avoided entirely.
- **Cache** — API responses carry `Cache-Control: no-store` from the
  server middleware; Vercel only needs to not override them (rewrites
  pass response headers through unchanged).
- **CSRF** — `TRUSTED_ORIGINS` on the API lists exactly the Vercel
  origin (`https://<app>.vercel.app`); nothing else gets credentialed
  mutations.
- **Secrets** — none in the Vite bundle; `VITE_*` vars would be public
  so the bundle carries no DSN/tokens at all (the API base is same-
  origin `/api`).
- **Hobby cron** — once/day minimum interval; cannot drive the 60 s
  engine. No cron configured here.

## Budget

100 GB Fast Data Transfer covers the SPA + API proxy traffic by a wide
margin. Hobby pauses (not bills) on overage — acceptable.
