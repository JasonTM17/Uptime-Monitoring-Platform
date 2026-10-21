import {
  QueryCache,
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import type { ReactNode } from "react";
import { ApiError } from "../lib/api/client";
import { emitSessionEvent } from "../lib/api/sessionEvents";

// One client per session scope — identity/role changes invalidate
// everything; a stale response must never hydrate a new identity.
export function makeQueryClient() {
  return new QueryClient({
    queryCache: new QueryCache({
      onError: (error, query) => {
        // Identity probes resolve 401 as state, not failure — only a
        // protected-query 401 means the session expired mid-use.
        const key = query.queryKey[0];
        if (
          error instanceof ApiError &&
          error.status === 401 &&
          key !== "me" &&
          key !== "capability"
        ) {
          emitSessionEvent();
        }
      },
    }),
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        retry: (count, err) => {
          const status = (err as { status?: number })?.status;
          if (status === 401 || status === 403 || status === 404) return false;
          return count < 2;
        },
        refetchOnWindowFocus: false,
      },
    },
  });
}

export function Providers({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={makeQueryClient()}>
      {children}
    </QueryClientProvider>
  );
}
