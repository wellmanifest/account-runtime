# Ticket 001: Define account runtime and identity graph standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: BLOCKED
- **Workflow state**: EDIT
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

- [ ] AC-01: A closed Draft 2020-12 schema defines graph, runtime binding,
  invocation and receipt document variants.
- [ ] AC-02: Observation distinguishes evidence, inference and verification;
  a detected executable or auth profile cannot be reported as ready.
- [ ] AC-03: GBNF accepts only the invocation AST intersection accepted by the
  schema and rejects raw argv, shell, secret material and transport overrides.
- [ ] AC-04: Runtime bindings are scoped to identity, provider, tool, project,
  container and MCP endpoint, with explicit persistence and readiness states.
- [ ] AC-05: Receipts preserve query→artifact provenance without email,
  credential values, prompts or model output in logs.
- [ ] AC-06: Architecture and logic flow contain Mermaid diagrams, failure
  states and an adoption crosswalk to POA, DSL and deployment.
- [ ] AC-07: Governance, schema metaschema, positive/adversarial conformance and
  isolated networkless Docker validation pass.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)

## Authorization

The request to continue and create missing standards is recorded as
`SESSION_EXECUTION_AUTHORIZATION` for `intent.json`. It is not trusted merge
approval and does not authorize remote creation, credential access or runtime
execution against provider accounts.

## Current blocker

The repository has no initial Git commit. The mandatory bounded-delivery
contract therefore cannot bind `acceptedBaseSha` to a real reviewed baseline,
and the governance gate returns `GOV-DELIVERY-001`. A local baseline commit
requires explicit commit authority; no placeholder SHA or policy bypass will
be used.
