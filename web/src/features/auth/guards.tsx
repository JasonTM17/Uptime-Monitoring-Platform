import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useSession } from "./session";

function Splash() {
  return (
    <div role="status" className="p-8 text-fg-muted">
      Loading…
    </div>
  );
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { status } = useSession();
  const loc = useLocation();
  if (status === "loading") return <Splash />;
  if (status === "anonymous") {
    return <Navigate to="/login" state={{ from: loc.pathname }} replace />;
  }
  return children;
}

export function RequireGuest({ children }: { children: ReactNode }) {
  const { status } = useSession();
  const loc = useLocation();
  if (status === "loading") return <Splash />;
  if (status === "authenticated") {
    const back = (loc.state as { from?: string } | null)?.from;
    return <Navigate to={back ?? "/"} replace />;
  }
  return children;
}

// Capability-gated admin shell — the server still authorizes each
// route; this only prevents a pointless navigation.
export function RequireAdmin({ children }: { children: ReactNode }) {
  const { status, canAdmin } = useSession();
  const loc = useLocation();
  if (status === "loading" || (status === "authenticated" && canAdmin === null)) {
    return <Splash />;
  }
  if (status === "anonymous") {
    return <Navigate to="/login" state={{ from: loc.pathname }} replace />;
  }
  if (canAdmin === false) {
    return (
      <div role="alert" className="p-8">
        <h1 className="text-lg font-semibold text-denied-fg">Access denied</h1>
        <p className="text-fg-muted">
          This area requires administrative permissions.
        </p>
      </div>
    );
  }
  return children;
}
