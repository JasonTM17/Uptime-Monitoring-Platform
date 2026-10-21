import { Route, Routes } from "react-router-dom";
import { RequireAdmin, RequireAuth, RequireGuest } from "../features/auth/guards";
import { DashboardPage } from "../features/dashboard/DashboardPage";
import { MonitorDetailPage } from "../features/monitors/MonitorDetailPage";
import { MonitorsPage } from "../features/monitors/MonitorsPage";
import { LoginPage } from "../features/auth/LoginPage";
import { RegisterPage } from "../features/auth/RegisterPage";
import { SessionProvider } from "../features/auth/session";
import { AppShell } from "./AppShell";

// Placeholder body for routes owned by later cards (C69+); the shell,
// guards and nav exist now but these aren't the delivered features.
function Pending({ title }: { title: string }) {
  return <h1 className="text-lg font-semibold">{title}</h1>;
}

function NotFound() {
  return (
    <div role="alert" className="p-8">
      <h1 className="text-lg font-semibold">Page not found</h1>
      <p className="text-fg-muted">That route doesn’t exist.</p>
    </div>
  );
}

export function App() {
  return (
    <SessionProvider>
      <Routes>
        <Route
          path="/login"
          element={
            <RequireGuest>
              <LoginPage />
            </RequireGuest>
          }
        />
        <Route
          path="/register"
          element={
            <RequireGuest>
              <RegisterPage />
            </RequireGuest>
          }
        />
        <Route
          element={
            <RequireAuth>
              <AppShell />
            </RequireAuth>
          }
        >
          <Route path="/" element={<DashboardPage />} />
          <Route path="/monitors" element={<MonitorsPage />} />
          <Route path="/monitors/:id" element={<MonitorDetailPage />} />
          <Route path="/incidents" element={<Pending title="Incidents" />} />
          <Route path="/channels" element={<Pending title="Channels" />} />
          <Route path="/settings" element={<Pending title="Settings" />} />
          <Route
            path="/admin"
            element={
              <RequireAdmin>
                <Pending title="Admin overview" />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/*"
            element={
              <RequireAdmin>
                <Pending title="Admin" />
              </RequireAdmin>
            }
          />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
    </SessionProvider>
  );
}
