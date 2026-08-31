# Ticket 002: Standardize account-derived service access with Digital Twin readback

- **ID**: ticket-002
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-08-31

## Goal and scope

Extend the existing account-runtime standard with a provider-neutral,
secret-free contract that answers how a service can be observed or provisioned
through an already verified parent account. The catalog binds account evidence,
Vault metadata, reviewed connector capabilities, an exact operation, external
authority controls and a revisioned Digital Twin readback.

The standard composes `wellmanifest/twin-lifecycle`,
`wellmanifest/authority-lifecycle` and `wellmanifest/auth-lifecycle`; it does
not take ownership of their lifecycle, grant or authentication semantics.
Provider adapters and running services remain outside Wellmanifest.

## Acceptance criteria

- [x] AC-01: A closed `wellmanifest.service-access-catalog/v1` schema defines
  service types, observe/provision profiles, explicit gaps and evidence-only
  boundaries.
- [x] AC-02: Provision profiles require a verified parent account, immutable
  operation references, two-phase exact-plan control, an external single-use
  grant and independent revisioned Twin readback.
- [x] AC-03: Provider-child account creation is representable only through a
  declared producer intent; primary provider/tenant account creation remains
  forbidden, and observe profiles cannot carry mutation operations.
- [x] AC-04: The neutral example covers API credentials, subscriptions and
  SSH/SFTP access while recording database provisioning as a knowledge gap.
- [x] AC-05: Positive and adversarial conformance rejects secret material,
  unverified accounts, mutable operation refs, unsafe authority, missing
  readback, undeclared service types and gap/profile contradictions.
- [x] AC-06: Dependency-free, networkless Docker and governance validation pass.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)

## Authorization

The user's request to examine existing Wellmanifest standards and implement or
extend the correct one is recorded as `SESSION_EXECUTION_AUTHORIZATION` for the
bounded `intent.json`. It authorizes implementation and the repository's
protected publication path, but not secret access, provider mutations or
self-issued merge authority.

## Placement

`HOME wellmanifest`, `shape domain_pack`; runtime owners remain adopters such
as Subactor. The concrete Subactor catalog ADOPTS this standard; the standard
does not HOME Subactor APIs, daemons, connectors or Vault.

## Validation status

- Draft 2020-12 metaschema and neutral example validation: passed.
- Dependency-free conformance: five positive document variants passed;
  existing 15 account-runtime and new 16 service-access adversarial cases were
  rejected. Output digest: `sha256:827e1e5083d156ed47ab5311836a566c95ac102023c625257cd2638ad028fbb7`.
- Networkless, read-only, capability-dropped Docker conformance: passed.
- Governance: `GOV-PASS` with zero errors and warnings.
- Python compilation and `git diff --check`: passed.
