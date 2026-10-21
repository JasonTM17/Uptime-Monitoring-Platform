# SSRF boundary — checker destination policy

The monitor checker fetches operator-supplied URLs. Without a boundary
that is a textbook SSRF primitive: an owner could point a "monitor" at
cloud metadata (`169.254.169.254`), internal services, or loopback and
read the results through status/latency side channels.

## Where the boundary lives

1. **Syntax gate (C19, monitor create/patch).** Schemes limited to
   `http`/`https`; userinfo, fragments, explicit ports, and whitespace
   rejected; obvious non-public literals refused early. This is a UX
   gate, NOT the security boundary — strings can't prove routability.
2. **Resolution gate (C28).** Every DNS answer is classified with
   `netip` AFTER unmapping IPv4-mapped IPv6. ANY denied answer fails
   the whole resolution — a hostname is dialable only when every
   returned address is public global unicast.
3. **Dial gate (C29).** The transport dials the validated IP:port
   directly; TLS `ServerName` and certificate verification still use
   the ORIGINAL hostname. No proxy, no redirects, no keep-alive
   coalescing — the connection cannot escape the approved set.

## Threat model

| Attack | Mitigation |
|---|---|
| Direct internal IP (10.x, 192.168.x, fd…) | denied at syntax + resolution gates |
| DNS A/AAAA mix of public + private | whole resolution fails on ANY denied answer |
| IPv4-mapped IPv6 (`::ffff:10.x`) | unmapped before classification |
| Encoded literals (hex `0x7f000001`, decimal, octal) | parsed as addresses, then classified |
| CGNAT `100.64.0.0/10` | denied — commonly missed by RFC1918-only checks |
| DNS rebinding between validate and dial | dial pins the validated address — no second lookup |
| Redirect to internal host | redirects refused entirely (no second dial) |
| `HTTP_PROXY`/`HTTPS_PROXY` env | transport sets `Proxy: nil` |
| Zone-scoped link-local (`fe80::1%eth0`) | denied — scoped addresses never dialable |
| 6to4 `2002::/16` embedding private v4 | denied |

## Explicit limits

- The boundary proves the *dialed destination* is public. It does not
  prove OS-level egress isolation (a compromised process could open
  raw sockets — out of scope).
- `0.0.0.0`/`::` reach the local stack on most OSes — denied.
- Resolution results are per-attempt, never cached indefinitely; DNS
  changes are picked up on the next check.
- Denied destinations produce `OutcomePolicyBlocked` — collector-side
  evidence that never moves a monitor's health.

## Fixture oracle

`internal/checker/testdata/destination-policy.json` captures the
expected decisions independently of the implementation, sourced from
the IANA special-purpose registries (dates recorded in the file). The
integrity harness proves the oracle is well-formed; implementation
parity is proven in C28.

## Observed verification evidence (C32 snapshot)

- `go test ./internal/checker -count=1` — PASS (~8.6s): full fixture
  oracle, pinned-dial recorder, TLS CA composition, bounded body,
  cleanup counters, cancel/rebind/redirect negatives, deadline
  taxonomy.
- `go test -race ./internal/checker -count=1` — PASS (~8.9s): 16-way
  concurrent checks, isolated target transports, zero reports.
- Zero-dial oracle proven non-vacuous by `TestUnsafeSubstituteWouldFail`:
  a deliberately unsafe validate-then-default-dial composition DOES
  reach the rebound private answer — the assertions discriminate the
  pinned path from the unsafe one.
- Response body cap: 64 KiB read bound; body is never persisted and
  never surfaces in an Observation. `Content-Length` is never trusted
  for allocation.
- Deadline taxonomy: DNS→`DNS_ERROR`, transport→`CONNECT_ERROR`,
  x509→`TLS_ERROR`, budget expiry at any phase→`TIMEOUT`, caller
  cancel at any phase→`CANCELED`, anything else→`INTERNAL_ERROR`.
  Only the first six are eligible health evidence; policy/cancel/
  internal can never move a failure streak.
- Limits: the boundary proves the *dialed destination*, not OS egress
  isolation. Unit/integration evidence only — not a network sandbox
  proof.
