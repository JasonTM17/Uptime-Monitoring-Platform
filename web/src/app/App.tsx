import { Route, Routes } from "react-router-dom";
import { RequireAdmin, RequireAuth, RequireGuest } from "../features/auth/guards";
import { DashboardPage } from "../features/dashboard/DashboardPage";
import { IncidentsPage } from "../features/incidents/IncidentsPage";
import { ChannelsPage } from "../features/notifications/ChannelsPage";
import { SettingsPage } from "../features/settings/SettingsPage";
import { OverviewPage } from "../features/admin/OverviewPage";
import { UsersPage } from "../features/admin/identity/UsersPage";
import { UserDetailPage } from "../features/admin/identity/UserDetailPage";
import { RolesPage } from "../features/admin/identity/RolesPage";
import { AuditDetailPage } from "../features/admin/operations/AuditDetailPage";
import { AuditPage } from "../features/admin/operations/AuditPage";
import { GlobalMonitorsPage } from "../features/admin/operations/GlobalMonitorsPage";
import { OperationsPage } from "../features/admin/operations/OperationsPage";
import { OutboxPage } from "../features/admin/operations/OutboxPage";
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
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/channels" element={<ChannelsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route
            path="/admin"
            element={
              <RequireAdmin>
                <OverviewPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/users"
            element={
              <RequireAdmin>
                <UsersPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/users/:id"
            element={
              <RequireAdmin>
                <UserDetailPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/roles"
            element={
              <RequireAdmin>
                <RolesPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/monitors"
            element={
              <RequireAdmin>
                <GlobalMonitorsPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/operations"
            element={
              <RequireAdmin>
                <OperationsPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/outbox"
            element={
              <RequireAdmin>
                <OutboxPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/audit"
            element={
              <RequireAdmin>
                <AuditPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/audit/:id"
            element={
              <RequireAdmin>
                <AuditDetailPage />
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
