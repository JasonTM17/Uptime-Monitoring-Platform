// Tiny auth-event bus: the query cache reports mid-session 401s here
// and the SessionProvider owns what happens next (clear + redirect).
// Keeps the fetch layer free of router/react knowledge.
export type SessionEvent = "unauthorized";
type Listener = () => void;

const listeners = new Set<Listener>();

export function onSessionEvent(fn: Listener): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function emitSessionEvent(): void {
  for (const fn of listeners) fn();
}
