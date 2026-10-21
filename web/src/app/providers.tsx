import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

// One client per session scope — identity/role changes invalidate
// everything; a stale response must never hydrate a new identity.
export function makeQueryClient() {
  return new QueryClient({
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
