import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "../../../lib/api/client";
import { useSession } from "../../auth/session";
import { AdminActionDialog, type AdminAction } from "../AdminActionDialog";
import { createRole, fetchRoleCatalog, updateRole, type AdminRole } from "../queries";

function PermissionMatrix({
  catalog,
  ceiling,
  selected,
  onToggle,
  readOnly,
}: {
  catalog: { id?: string; requires?: string[] }[];
  ceiling: string[];
  selected: Set<string>;
  onToggle?: (id: string) => void;
  readOnly?: boolean;
}) {
  return (
    <table className="w-full text-left font-mono text-xs" aria-label="Permission catalog">
      <thead>
        <tr className="border-b border-border text-fg-muted">
          <th scope="col" className="px-2 py-1 font-medium">Permission</th>
          <th scope="col" className="px-2 py-1 font-medium">Requires</th>
          <th scope="col" className="px-2 py-1 font-medium">Ceiling</th>
          {!readOnly && <th scope="col" className="px-2 py-1 font-medium">Grant</th>}
        </tr>
      </thead>
      <tbody>
        {catalog.map((p) => {
          const overCeiling = !ceiling.includes(p.id!);
          return (
            <tr key={p.id} className="border-b border-border-subtle last:border-0">
              <td className="px-2 py-1 text-fg">{p.id}</td>
              <td className="px-2 py-1 text-fg-muted">
                {(p.requires ?? []).join(", ") || "—"}
              </td>
              <td className="px-2 py-1">
                {overCeiling ? (
                  <span className="text-stale-fg">over ceiling</span>
                ) : (
                  <span className="text-fg-muted">delegable</span>
                )}
              </td>
              {!readOnly && (
                <td className="px-2 py-1">
                  <input
                    type="checkbox"
                    aria-label={`grant ${p.id}`}
                    checked={selected.has(p.id!)}
                    disabled={overCeiling}
                    onChange={() => onToggle?.(p.id!)}
                    className="accent-accent"
                  />
                </td>
              )}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function RoleEditor({
  role,
  catalog,
  ceiling,
  onSubmit,
  onCancel,
  onDone,
}: {
  role: AdminRole | null;
  catalog: { id?: string; requires?: string[] }[];
  ceiling: string[];
  onSubmit: (a: AdminAction<unknown>) => void;
  onCancel: () => void;
  onDone: (saved: boolean) => void;
}) {
  const [code, setCode] = useState(role?.code ?? "");
  const [name, setName] = useState(role?.name ?? "");
  const [selected, setSelected] = useState<Set<string>>(
    new Set(role?.permissions ?? []),
  );
  const [hint, setHint] = useState<string | null>(null);
  const catalogById = new Map(catalog.map((p) => [p.id!, p]));

  const toggle = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
      // surface unmet prerequisites — the server enforces with a 422
      const missing = (catalogById.get(id)?.requires ?? []).filter(
        (r) => !next.has(r),
      );
      setHint(
        missing.length
          ? `${id} requires ${missing.join(", ")} — the server rejects grants without them (422 missing_permissions).`
          : null,
      );
    }
    setSelected(next);
  };

  const missingAll = [...selected].flatMap((id) =>
    (catalogById.get(id)?.requires ?? []).filter((r) => !selected.has(r)),
  );

  return (
    <form
      aria-label={role ? `Edit role ${role.code}` : "Create role"}
      className="space-y-3 rounded border border-border bg-container p-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (role) {
          onSubmit({
            title: `Update role ${role.code}`,
            summary: `Replace the grant set of ${role.code} — every holder's security epoch advances on commit.`,
            confirmLabel: "Update role",
            danger: true,
            run: (reason, idem) =>
              updateRole(role.id!, name || undefined, [...selected], role.version!, reason, idem),
            onDone: () => onDone(true),
          });
        } else {
          onSubmit({
            title: "Create custom role",
            summary: `Create role ${code || "?"} with the selected grants — bounded by the delegation ceiling.`,
            confirmLabel: "Create role",
            run: (reason, idem) =>
              createRole(code, name, [...selected], reason, idem),
            onDone: () => onDone(true),
          });
        }
      }}
    >
      {!role && (
        <label className="block text-sm">
          <span className="text-fg-secondary">Code</span>
          <input
            value={code}
            onChange={(e) => setCode(e.target.value.toUpperCase())}
            required
            minLength={2}
            maxLength={40}
            pattern="[A-Z][A-Z0-9_]{1,39}"
            placeholder="AUDIT_READER"
            className="mt-1 block w-56 rounded border border-border bg-bg px-2 py-1 font-mono text-fg"
          />
        </label>
      )}
      <label className="block text-sm">
        <span className="text-fg-secondary">Name</span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          maxLength={80}
          className="mt-1 block w-72 rounded border border-border bg-bg px-2 py-1 text-fg"
        />
      </label>
      <PermissionMatrix
        catalog={catalog}
        ceiling={ceiling}
        selected={selected}
        onToggle={toggle}
      />
      {hint && (
        <p role="note" className="text-xs text-stale-fg">
          {hint}
        </p>
      )}
      {missingAll.length > 0 && (
        <p role="note" className="text-xs text-stale-fg">
          Unmet prerequisites: {[...new Set(missingAll)].join(", ")} — submit
          will be rejected (422 missing_permissions); the server never
          auto-grants them.
        </p>
      )}
      <div className="flex gap-2">
        <button
          type="submit"
          disabled={(!role && !code) || !name}
          className="rounded bg-accent px-3 py-1 text-sm font-medium text-accent-fg disabled:opacity-50"
        >
          {role ? "Update…" : "Create…"}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded border border-border px-3 py-1 text-sm text-fg-secondary"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

export function RolesPage() {
  const { user } = useSession();
  const qc = useQueryClient();
  const catalog = useQuery({
    queryKey: ["admin-roles", user?.id],
    queryFn: ({ signal }) => fetchRoleCatalog(signal),
  });
  const [editing, setEditing] = useState<AdminRole | null | "new">(null);
  const [action, setAction] = useState<AdminAction<unknown> | null>(null);
  const forbidden =
    catalog.error instanceof ApiError && catalog.error.status === 403;
  const d = catalog.data;
  const ceiling = d?.delegation_ceiling ?? [];

  return (
    <div className="max-w-4xl space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Roles</h1>
        <p className="mt-1 text-sm text-fg-secondary">
          Permission catalog and delegation ceiling — grants over the ceiling
          are denied server-side; preset roles are immutable.
        </p>
      </header>

      {catalog.isPending ? (
        <div role="status" className="text-fg-muted">Loading roles…</div>
      ) : forbidden ? (
        <div role="alert" className="rounded border border-border bg-container p-3 text-sm text-fg-secondary">
          Your role doesn’t include <code className="font-mono">roles:read</code>{" "}
          — this section is denied.
        </div>
      ) : catalog.isError || !d ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load roles.{" "}
          <button type="button" onClick={() => catalog.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : (
        <>
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-medium text-fg-secondary">
              {d.roles?.length ?? 0} roles
            </h2>
            {editing === null && (
              <button
                type="button"
                onClick={() => setEditing("new")}
                className="rounded border border-border px-2 py-0.5 text-xs text-fg-secondary hover:text-fg"
              >
                New custom role
              </button>
            )}
          </div>

          <ul className="grid gap-2 sm:grid-cols-2" aria-label="Roles">
            {(d.roles ?? []).map((r) => (
              <li key={r.id} className="rounded border border-border bg-container p-3">
                <div className="flex items-center gap-2">
                  <strong className="font-mono text-sm text-fg">{r.code}</strong>
                  {r.is_preset && (
                    <span className="rounded border border-border px-1 py-0.5 font-mono text-[10px] uppercase text-fg-muted">
                      preset
                    </span>
                  )}
                  <span className="ml-auto font-mono text-xs text-fg-muted">
                    v{r.version}
                  </span>
                  {!r.is_preset && editing === null && (
                    <button
                      type="button"
                      onClick={() => setEditing(r)}
                      className="rounded border border-border px-2 py-0.5 text-xs text-fg-secondary hover:text-fg"
                    >
                      Edit…
                    </button>
                  )}
                </div>
                <p className="mt-1 text-xs text-fg-secondary">{r.name}</p>
                <p className="mt-1 break-all font-mono text-xs text-fg-muted">
                  {(r.permissions ?? []).join(", ") || "no grants"}
                </p>
              </li>
            ))}
          </ul>

          {editing !== null && (
            <RoleEditor
              role={editing === "new" ? null : editing}
              catalog={d.catalog ?? []}
              ceiling={ceiling}
              onSubmit={(a) => {
                setEditing(null);
                setAction(a);
              }}
              onCancel={() => setEditing(null)}
              onDone={() => {
                setEditing(null);
                qc.invalidateQueries({ queryKey: ["admin-roles"] });
              }}
            />
          )}

          <section aria-label="Permission catalog">
            <h2 className="mb-2 text-sm font-medium text-fg-secondary">
              Catalog (read-only reference)
            </h2>
            <div className="overflow-x-auto rounded border border-border bg-container">
              <PermissionMatrix
                catalog={d.catalog ?? []}
                ceiling={ceiling}
                selected={new Set()}
                readOnly
              />
            </div>
          </section>
        </>
      )}

      <AdminActionDialog action={action} onClose={() => setAction(null)} />
    </div>
  );
}
