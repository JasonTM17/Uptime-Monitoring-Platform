import { Route, Routes } from "react-router-dom";

// Scaffold shell — semantic landmarks and the fallback route exist
// now; feature pages land in their own cards (C69+).
export function App() {
  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-container px-4 py-2">
        <div className="flex items-center gap-3">
          <span className="font-mono text-sm font-semibold tracking-wide">
            UPTIME CONSOLE
          </span>
          <nav aria-label="Primary" className="flex gap-3 text-fg-secondary">
            <span aria-current="page">Dashboard</span>
          </nav>
        </div>
      </header>
      <main className="p-4">
        <Routes>
          <Route
            path="/"
            element={
              <h1 className="text-lg font-semibold">Dashboard</h1>
            }
          />
          <Route
            path="*"
            element={
              <div role="alert">
                <h1 className="text-lg font-semibold">Page not found</h1>
                <p className="text-fg-muted">That route doesn’t exist.</p>
              </div>
            }
          />
        </Routes>
      </main>
    </div>
  );
}
