# Ticket 001: Define account runtime and identity graph standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-08-12

## Goal and scope

Define a reusable standard for representing locally observed login identities,
service accounts, provider/tool bindings, persistent isolated runtimes and
scoped invocations. It generalizes the verified Inventory → Hub → Subactor
experience without making browser databases, containers, MCP, an LLM or a DSL
document an authority.

The standard owns document semantics and conformance only. Provider adapters,
credential stores, container images, KVM/noVNC implementations and production
grants remain external capabilities.

## Acceptance criteria

- [x] AC-01: A closed Draft 2020-12 schema defines graph, runtime binding,
  invocation and receipt document variants.
- [x] AC-02: Observation distinguishes evidence, inference and verification;
  a detected executable or auth profile cannot be reported as ready.
- [x] AC-03: GBNF accepts only the invocation AST intersection accepted by the
  schema and rejects raw argv, shell, secret material and transport overrides.
- [x] AC-04: Runtime bindings are scoped to identity, provider, tool, project,
  container and MCP endpoint, with explicit persistence and readiness states.
- [x] AC-05: Receipts preserve query→artifact provenance without email,
  credential values, prompts or model output in logs.
- [x] AC-06: Architecture and logic flow contain Mermaid diagrams, failure
  states and an adoption crosswalk to POA, DSL and deployment.
- [x] AC-07: Governance, schema metaschema, positive/adversarial conformance and
  isolated networkless Docker validation pass.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)

## Authorization

The request to continue and create missing standards is recorded as
`SESSION_EXECUTION_AUTHORIZATION` for `intent.json`. The subsequent explicit
request to push the changes authorizes creation of the public repository,
committing this bounded diff, pushing its ticket branch and opening a pull
request. It is not trusted merge approval and does not authorize credential
access or runtime execution against provider accounts.

## Baseline resolution

The user explicitly authorized a local, non-published baseline commit. Bounded
delivery now binds `acceptedBaseSha` to
`fa36b9d6f3f61c5d586607a79b0a8fc39f2c6b44`; no placeholder SHA or policy
bypass was used.

## Validation status

- Governance against exact baseline: passed with zero errors and warnings.
- Draft 2020-12 metaschema: passed.
- Four positive variants and 15 adversarial cases: passed.
- Networkless, read-only, capability-dropped Docker conformance: passed.
- `git diff --check`: passed.
- Publication revalidation passed with `GOV-PASS` (0 errors, 0 warnings), four
  positive variants and 15 adversarial rejections. Ticket-branch publication
  is authorized; trusted exact-head review and merge remain pending.
