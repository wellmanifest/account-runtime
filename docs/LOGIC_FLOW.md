# Account Runtime logic flow

## Observation and resolution

```mermaid
sequenceDiagram
    participant S as Credential store
    participant O as Observer
    participant G as Graph
    participant R as Resolver/reviewer
    participant H as Runtime hub
    S->>O: origin plus account handle plus secret fields
    O->>O: discard secret values
    O->>G: identity service evidence and observed link
    G->>R: unresolved and inferred links
    R->>G: reviewed provider mapping or retained generic service
    G->>H: exact graph digest plus identity/provider/tool selection
    H->>H: create or update isolated binding
```

Deleting an unclassified service is not a resolution. The graph preserves it
as `generic-service` or `unknown` until evidence supports a provider mapping.

## Readiness state machine

```mermaid
stateDiagram-v2
    [*] --> InitializationRequired
    InitializationRequired --> SessionUnverified: executable and profile detected
    SessionUnverified --> Ready: provider authentication plus endpoint plus project verified
    SessionUnverified --> InitializationRequired: profile missing or invalid
    Ready --> Degraded: endpoint or project probe stale/red
    Ready --> SessionUnverified: restart requires session verification
    Ready --> Revoked: credential/session revoked
    Degraded --> Ready: all probes reverified
    Degraded --> InitializationRequired: executable/project unavailable
    Revoked --> InitializationRequired: explicit reinitialization
```

The derived `ready` predicate is:

```text
installation == available
AND authentication == verified
AND endpoint == verified
AND project IN [mounted_read_only, mounted_read_write]
AND every observation is current under local policy
```

No softer signal can compensate for a red or unknown predicate.

## Invocation path

```mermaid
sequenceDiagram
    participant A as Subactor/agent
    participant C as POA compiler
    participant P as Policy authority
    participant M as Scoped MCP
    participant R as Account runtime
    participant V as Verifier
    participant S as Artifact store
    A->>C: schema+GBNF request with artifact refs
    C->>C: bind runtime identity provider tool project and limits
    C-->>A: secret-free plan and hashes
    A->>P: request exact single-use grant
    P-->>M: grant or denial
    M->>M: revalidate schema grammar origin endpoint and plan hash
    M->>R: bounded tool invocation
    R->>S: write versioned output artifact
    R->>V: execution and artifact evidence
    V-->>A: redacted typed receipt
```

An invocation that needs a different account, provider, tool, project, prompt,
input, limit or output contract is a new plan and needs a fresh grant.

## Restart and session persistence

```mermaid
flowchart TD
    Stop[Container stops] --> Volume[Per-account profile volume retained]
    Volume --> Start[Container restarts under declared policy]
    Start --> Mount[Project and profile mounted]
    Mount --> Probe[Provider session and endpoint probed]
    Probe -->|verified| Ready[Ready]
    Probe -->|unknown or expired| Unverified[Session unverified]
    Unverified --> Human[Human login through bounded noVNC/KVM]
    Human --> Probe
```

The profile volume is necessary for persistence but insufficient for readiness.
An implementation MUST keep the runtime non-ready until post-restart probes
confirm the provider session.

## Failure routing

| Failure | Required outcome | Next safe action |
| --- | --- | --- |
| Unknown service classification | retain observed link | review or add mapping evidence |
| Executable missing | `initialization_required` | install through governed image update |
| Profile only detected | `auth_unverified` | provider verification or human login |
| Foreign endpoint/identity/tool | `denied` | create a new exact plan |
| Schema/GBNF mismatch | `denied` | regenerate a conforming request |
| Runtime mutation but output unverified | `executed_unverified` | preserve evidence and escalate/retry under new plan |
| Restart invalidates session | `auth_unverified` | reauthenticate; never reuse readiness claim |
| Clipboard policy violation | `denied` | use bounded artifact/text broker |

Every terminal branch emits a receipt, including denial and initialization.
