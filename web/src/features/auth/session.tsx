import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { useLocation, useNavigate } from "react-router-dom";
import type { components } from "../../lib/api/schema";
import { onSessionEvent } from "../../lib/api/sessionEvents";
import {
  fetchMe,
  login as apiLogin,
  logout as apiLogout,
  probeAdmin,
  register as apiRegister,
  type MeData,
} from "./queries";

export type SessionStatus = "loading" | "anonymous" | "authenticated";

export interface SessionContextValue {
  status: SessionStatus;
  user: MeData["user"] | null;
  sessionExpiresAt: string | null;
  // null = probe still running; false = no platform:read grant.
  canAdmin: boolean | null;
  expiredNotice: boolean;
  login: (input: components["schemas"]["LoginInput"]) => Promise<void>;
  register: (input: components["schemas"]["RegisterInput"]) => Promise<void>;
  logout: () => Promise<void>;
}

const Ctx = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const [expiredNotice, setExpiredNotice] = useState(false);
  // After logout the server cookie may still be valid (logout request
  // failed); suppress /me-driven re-auth until a fresh login or reload.
  const [forcedOut, setForcedOut] = useState(false);

  const me = useQuery({
    queryKey: ["me"],
    queryFn: ({ signal }) => fetchMe(signal),
    retry: false,
    staleTime: 30_000,
  });

  const meData = me.data ?? null;
  const authed = meData !== null;
  const user = meData?.user ?? null;

  const adminProbe = useQuery({
    queryKey: ["capability", "admin", user?.id ?? "none"],
    queryFn: ({ signal }) => probeAdmin(signal),
    enabled: authed,
    retry: false,
    staleTime: 5 * 60_000,
  });

  // clear() cancels in-flight requests and evicts every cached
  // identity response — a stale promise cannot hydrate the next
  // identity because its query instance no longer exists.
  const endSession = useCallback(
    (notice: boolean) => {
      setExpiredNotice(notice);
      qc.clear();
    },
    [qc],
  );

  // Mid-session 401 on any non-bootstrap query → session is gone.
  // Read the live cache, not a closure — a 401 that lands between /me
  // resolving and this effect re-registering must still end the session.
  useEffect(
    () =>
      onSessionEvent(() => {
        if (qc.getQueryData<MeData>(["me"])) endSession(true);
      }),
    [qc, endSession],
  );

  const doLogin = useMutation({
    mutationFn: apiLogin,
    onSuccess: (data) => {
      setExpiredNotice(false);
      setForcedOut(false);
      qc.clear();
      if (data.data) qc.setQueryData<MeData>(["me"], data.data);
    },
  });

  const doRegister = useMutation({ mutationFn: apiRegister });

  const doLogout = useMutation({
    mutationFn: apiLogout,
    // Server logout is idempotent; even on failure the local identity
    // ends — the cookie may linger but stale data must not.
    onSettled: () => {
      setForcedOut(true);
      endSession(false);
    },
  });

  const effAuthed = authed && !forcedOut;
  const value: SessionContextValue = {
    status: me.isPending
      ? "loading"
      : effAuthed
        ? "authenticated"
        : "anonymous",
    user: effAuthed ? user : null,
    sessionExpiresAt: effAuthed ? (meData?.session_expires_at ?? null) : null,
    canAdmin: effAuthed ? (adminProbe.data ?? null) : null,
    expiredNotice,
    login: async (input) => {
      await doLogin.mutateAsync(input);
    },
    register: async (input) => {
      await doRegister.mutateAsync(input);
    },
    logout: async () => {
      // A failed call still ends the local session — the cookie may
      // persist, but stale identity data must not.
      try {
        await doLogout.mutateAsync();
      } catch {
        /* surfaced as "signed out locally" below */
      }
      navigate("/login", { replace: true, state: { from: location.pathname } });
    },
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession(): SessionContextValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSession outside SessionProvider");
  return v;
}
