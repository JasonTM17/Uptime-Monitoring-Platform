import { NavLink, Outlet } from "react-router-dom";
import { useSession } from "../features/auth/session";

interface NavItem {
  to: string;
  label: string;
  end?: boolean;
}

const ownNav: NavItem[] = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/monitors", label: "New monitor" },
  { to: "/incidents", label: "Incidents" },
  { to: "/channels", label: "Channels" },
  { to: "/settings", label: "Settings" },
];

const adminNav: NavItem[] = [
  { to: "/admin", label: "Overview", end: true },
  { to: "/admin/users", label: "Users" },
  { to: "/admin/roles", label: "Roles" },
  { to: "/admin/monitors", label: "Monitors" },
  { to: "/admin/operations", label: "Operations" },
  { to: "/admin/outbox", label: "Outbox" },
  { to: "/admin/audit", label: "Audit" },
];

function linkClass({ isActive }: { isActive: boolean }) {
  return isActive
    ? "rounded px-2 py-1 text-fg bg-overlay"
    : "rounded px-2 py-1 text-fg-secondary hover:text-fg";
}

export function AppShell() {
  const { user, canAdmin, logout } = useSession();

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-border bg-container px-4 py-2">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <span className="font-mono text-sm font-semibold tracking-wide">
            UPTIME CONSOLE
          </span>
          <nav aria-label="Primary" className="flex flex-wrap gap-1">
            {ownNav.map((l) => (
              <NavLink key={l.to} to={l.to} end={l.end} className={linkClass}>
                {l.label}
              </NavLink>
            ))}
          </nav>
          {canAdmin === true && (
            <nav
              aria-label="Administration"
              data-scope="global"
              className="flex flex-wrap gap-1 border-l border-border pl-4"
            >
              {adminNav.map((l) => (
                <NavLink key={l.to} to={l.to} end={l.end} className={linkClass}>
                  {l.label}
                </NavLink>
              ))}
            </nav>
          )}
          <div className="ml-auto flex min-w-0 items-center gap-3 text-sm">
            <span className="max-w-40 truncate text-fg-muted">{user?.email}</span>
            <button
              type="button"
              onClick={() => void logout()}
              className="rounded border border-border px-2 py-1 text-fg-secondary hover:text-fg"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="flex-1 p-4">
        <Outlet />
      </main>
    </div>
  );
}
