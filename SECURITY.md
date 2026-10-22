# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for suspected vulnerabilities.

Report privately through GitHub's
[private vulnerability reporting](../../security/advisories/new)
(“Report a vulnerability” on the Security tab). If that channel is
unavailable, open an issue with **no details** and ask for a private
contact path — do not include the finding itself.

What helps: affected endpoint/component, reproduction, and impact.

## Scope notes

This is a personal engineering project, not a production service.
There is no bug bounty and no response-time SLA. Reports are still
welcome and will be triaged honestly.

## Hardening surface (for reporters)

- SSRF: the HTTP checker validates every DNS answer and dials only
  validated public IPs; redirects are not followed. Private/reserved
  ranges are denied at both resolution and dial time.
- Auth: opaque server-side sessions, CSRF double-submit, rate limits,
  privileged step-up re-auth.
- Admin: permission catalog, append-only audit, security-epoch
  revocation.
- Channels: notification secrets are stored encrypted (keyring) and
  redacted in API output.
