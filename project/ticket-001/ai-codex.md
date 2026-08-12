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

## Blockers

- `GOV-DELIVERY-001`: no initial Git baseline exists, so an exact
  `acceptedBaseSha` cannot be declared. Further implementation validation is
  paused pending explicit authority for a local baseline commit.
- New authority remains required for destructive action, secret access, new
  external coordination, material objective expansion and trusted merge.

## Risks and controls

- Email addresses are restricted inventory data; invocations and receipts use
  opaque identity references and hashes.
- Credential discovery does not imply provider ownership or authenticated use.
- Persistence can preserve compromised sessions; health and revocation remain
  explicit runtime states.
- MCP is transport only; grants and intent checks stay external and exact-bound.
