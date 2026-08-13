---
participant-id: agent:codex
participant: codex
role: agent
ticket: ticket-001
---
# Participant: codex (AI agent)

## Understanding

The missing reusable element is the contract between account discovery and
execution. The same email may occur in many browser credentials, providers,
tools and containers; observed facts must remain distinct from inferred links
and verified authentication. A daily runtime must preserve profiles and
projects, but it must expose only bounded, account/tool-specific MCP actions.

## Execution plan

1. Define document variants and lifecycle states from current operational evidence.
2. Constrain invocations with a closed schema and matching GBNF.
3. Specify the identity→service→provider→tool→query→artifact graph and trust boundaries.
4. Add dependency-free positive and adversarial conformance tests.
5. Validate locally, through the governance gate and in networkless Docker.

## Actual changes

- Initialized the bounded ticket and recorded SESSION_EXECUTION_AUTHORIZATION
  from the request to execute this work.
- Adopted published `wellmanifest/new-project` v0.15.0 at its exact revision.
- Selected a separate standard because account/runtime semantics do not belong
  to generic POA, DSL or deployment contracts.
- Added the closed four-variant schema, request GBNF, dependency-free
  conformance runner and two visual architecture documents.
- Corrected the first receipt check so the explicit `secretFree: true`
  assertion is allowed while undeclared sensitive channels still fail closed.
- Validated the exact-baseline scope, metaschema, 15 adversarial rejections and
  isolated Docker execution.

## Blockers

- The initial-baseline blocker is resolved by the explicitly authorized local
  commit `fa36b9d6f3f61c5d586607a79b0a8fc39f2c6b44`.
- The user's explicit push request authorizes public remote creation,
  ticket-branch publication and pull-request creation for this bounded diff.
- New authority remains required for destructive action, secret access,
  material objective expansion and trusted merge.

## Risks and controls

- Email addresses are restricted inventory data; invocations and receipts use
  opaque identity references and hashes.
- Credential discovery does not imply provider ownership or authenticated use.
- Persistence can preserve compromised sessions; health and revocation remain
  explicit runtime states.
- MCP is transport only; grants and intent checks stay external and exact-bound.

## Acceptance evidence

- AC-01/02/04/05: `standard/account-runtime.schema.json` and conformance report.
- AC-03: `standard/account-runtime.v1.gbnf` plus raw argv/shell/credential cases.
- AC-06: `docs/ARCHITECTURE.md` and `docs/LOGIC_FLOW.md`.
- AC-07: raw outputs in `ai-codex-logs.txt`.
