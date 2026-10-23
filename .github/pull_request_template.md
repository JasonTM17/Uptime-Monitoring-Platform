## Summary

<!-- What changed and why — focus on intent, not file lists. -->

## Scope

<!-- What is deliberately NOT covered. -->

## Verification

<!-- Report honestly: PASS / FAIL / BLOCKED / NOT_RUN.
     Static checks and mocks do not prove live behavior. -->

- [ ] `gofmt` / `go vet` / `go test ./...`
- [ ] Integration tests (`-tags integration -p 1`) where touched
- [ ] Web: `tsc`, `eslint`, `vitest` where touched
- [ ] Acceptance gate (`scripts/accept-local.mjs`) if behavior changed

## Risk / follow-ups

<!-- Remaining risk, deferred items, and anything reviewers should
     scrutinize. -->
