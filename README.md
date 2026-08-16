# Wellmanifest Account Runtime

Experimental standard for evidence-backed account graphs and isolated,
provider-neutral tool runtimes. It defines how an implementation moves from
observed identity metadata to an externally authorized, account-scoped
invocation and a secret-free artifact receipt.

The normative artifacts live in `standard/`; architecture and adoption
guidance live in `docs/`. This repository never reads credentials or executes
provider tools.

## HOME vs ADOPT (boundary matrix)

`HOME` wellmanifest · `shape` domain_pack. This pack owns **isolated tool
runtime** evidence — not AuthN bind and not AuthZ issuance.

| Concern | HOME | This pack |
| --- | --- | --- |
| AuthN profiles / membership bind | `wellmanifest/auth-lifecycle` | **ADOPT-only** — binding ≠ credential transfer |
| AuthZ grants / leases | `wellmanifest/authority-lifecycle` | Consumes exact-plan grant; never mints |
| Isolated runtime / secret-free receipts | **this pack** | Owns |
| Commercial SaaS tenant state | `wellmanifest/saas-lifecycle` | Orthogonal inventory |
| Portal membership UX | `subactor/www-sub-actor` | Portal ≠ account-runtime |

See also: `docs/ARCHITECTURE.md`. Cross-ref LC-030 / auth-lifecycle SPEC ownership table.
