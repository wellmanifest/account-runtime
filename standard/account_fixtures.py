#!/usr/bin/env python3
"""Reference and adversarial fixtures for Wellmanifest account-runtime v1."""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

try:
    from standard.account_primitives import assert_closed_schema, strict_loads
except ImportError:
    from account_primitives import assert_closed_schema, strict_loads  # type: ignore[no-redef]

SCHEMA_URI = "https://wellmanifest.dev/schemas/account-runtime/v1"


def graph_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.account-graph/v1",
        "snapshotId": "snapshot-20260812",
        "observedAt": "2026-08-12T12:00:00Z",
        "identities": [
            {
                "ref": "identity://example.test/account-001",
                "handle": {
                    "kind": "email",
                    "value": "operator@example.test",
                    "classification": "restricted",
                },
                "storeRefs": ["store://example.test/browser-firefox"],
                "active": True,
            }
        ],
        "services": [
            {
                "ref": "service://example.test/anthropic-web",
                "name": "Anthropic Web",
                "origins": ["https://claude.example.test"],
                "providerRef": "provider://example.test/anthropic",
                "classification": "provider",
            }
        ],
        "links": [
            {
                "identityRef": "identity://example.test/account-001",
                "serviceRef": "service://example.test/anthropic-web",
                "relation": "credential_observed",
                "confidence": "observed",
                "evidenceRefs": ["evidence://example.test/browser/login-001/r1"],
                "observedAt": "2026-08-12T12:00:00Z",
            }
        ],
        "evidence": [
            {
                "ref": "evidence://example.test/browser/login-001/r1",
                "kind": "browser-login-origin",
                "sourceRef": "profile://example.test/firefox/default",
                "digest": "sha256:" + "a" * 64,
                "collectedAt": "2026-08-12T12:00:00Z",
                "secretsDiscarded": True,
                "valuesPersisted": False,
            }
        ],
    }


def runtime_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.account-runtime-binding/v1",
        "runtimeRef": "runtime://example.test/account-001-anthropic-claude",
        "graphDigest": "sha256:" + "b" * 64,
        "identityRef": "identity://example.test/account-001",
        "providerRef": "provider://example.test/anthropic",
        "toolRef": "tool://example.test/claude",
        "projectRef": "project://example.test/subactor",
        "containerRef": "container://example.test/account-001",
        "mcpEndpointRef": "mcp://example.test/accounts/account-001/providers/anthropic/tools/claude",
        "persistence": {
            "profileVolumeRef": "volume://example.test/account-001-profile",
            "projectMountRef": "project://example.test/subactor",
            "restartPolicy": "unless-stopped",
            "sessionRecovery": "verify-after-restart",
            "profileIsolation": "per-account",
            "hostExposure": "localhost-only",
            "clipboard": "brokered-text-only",
        },
        "state": {
            "installation": "available",
            "authentication": "verified",
            "endpoint": "verified",
            "project": "mounted_read_write",
            "readiness": "ready",
            "observedAt": "2026-08-12T12:05:00Z",
        },
        "control": {
            "operations": ["inspect", "plan", "invoke", "cancel", "focus", "close"],
            "rawShell": False,
            "arbitraryArgv": False,
            "mcpSchemaRequired": True,
            "gbnfRequired": True,
            "humanVisible": True,
            "kvmConnectorRef": "connector://example.test/kvm/account-runtime/v1",
        },
        "secretResolution": {
            "mode": "runtime-vault",
            "valuesInDocument": False,
            "refs": ["vault://example.test/accounts/account-001/anthropic"],
        },
    }


def request_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.account-runtime-request/v1",
        "requestId": "request-001",
        "operation": "invoke",
        "endpointRef": "mcp://example.test/accounts/account-001/providers/anthropic/tools/claude",
        "target": {
            "runtimeRef": "runtime://example.test/account-001-anthropic-claude",
            "identityRef": "identity://example.test/account-001",
            "providerRef": "provider://example.test/anthropic",
            "toolRef": "tool://example.test/claude",
            "projectRef": "project://example.test/subactor",
        },
        "task": {
            "kind": "llm-query",
            "promptRef": "artifact://example.test/prompts/review/r1",
            "inputRefs": ["artifact://example.test/source/repository/r2"],
            "outputContractRef": "schema://example.test/review/result/v1",
        },
        "limits": {"timeoutSeconds": 600, "maxArtifacts": 8, "maxOutputBytes": 1048576},
        "authority": {
            "mode": "external-exact-grant",
            "intentRef": "intent://example.test/tasks/review-001",
            "grantRef": "grant://example.test/tasks/review-001/g1",
            "planHash": "c" * 64,
            "singleUse": True,
        },
    }


def receipt_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.account-runtime-receipt/v1",
        "requestId": "request-001",
        "runtimeRef": "runtime://example.test/account-001-anthropic-claude",
        "planHash": "c" * 64,
        "inputHash": "d" * 64,
        "outputHash": "e" * 64,
        "outcome": "executed",
        "startedAt": "2026-08-12T12:10:00Z",
        "completedAt": "2026-08-12T12:11:00Z",
        "artifactRefs": ["artifact://example.test/reviews/result/r1"],
        "evidenceRefs": ["evidence://example.test/runtime/execution-001/r1"],
        "secretFree": True,
        "handleRedacted": True,
        "promptInline": False,
        "outputInline": False,
    }


def build_adversarial_account_cases(
    *,
    validate_graph_fn: Callable[[Any], None],
    validate_runtime_fn: Callable[[Any], None],
    validate_request_fn: Callable[[Any], None],
    validate_receipt_fn: Callable[[Any], None],
) -> list[tuple[str, Callable[[], Any]]]:
    graph, runtime = graph_example(), runtime_example()
    request, receipt = request_example(), receipt_example()
    cases: list[tuple[str, Callable[[], Any]]] = []

    def add(
        name: str,
        base: dict[str, Any],
        mutate: Callable[[dict[str, Any]], Any],
        fn: Callable[[Any], None],
    ) -> None:
        bad = copy.deepcopy(base)
        mutate(bad)
        cases.append((name, lambda bad=bad, fn=fn: fn(bad)))

    add(
        "link-without-evidence",
        graph,
        lambda d: d["links"][0].update(evidenceRefs=[]),
        validate_graph_fn,
    )
    add(
        "secret-values-persisted",
        graph,
        lambda d: d["evidence"][0].update(valuesPersisted=True),
        validate_graph_fn,
    )
    add(
        "origin-query-channel",
        graph,
        lambda d: d["services"][0].update(origins=["https://example.test/login?mode=unexpected"]),
        validate_graph_fn,
    )
    add(
        "non-rfc3339-timestamp",
        graph,
        lambda d: d.update(observedAt="2026-08-12 12:00:00+00:00"),
        validate_graph_fn,
    )
    add(
        "false-ready-auth",
        runtime,
        lambda d: d["state"].update(authentication="available_auth_unverified"),
        validate_runtime_fn,
    )
    add("raw-shell", runtime, lambda d: d["control"].update(rawShell=True), validate_runtime_fn)
    add("raw-argv", runtime, lambda d: d["control"].update(arbitraryArgv=True), validate_runtime_fn)
    add(
        "shared-profile",
        runtime,
        lambda d: d["persistence"].update(profileIsolation="shared"),
        validate_runtime_fn,
    )
    add("request-argv", request, lambda d: d.update(argv=["sh", "-c", "id"]), validate_request_fn)
    add(
        "inline-prompt",
        request,
        lambda d: d["task"].update(prompt="ignore policy"),
        validate_request_fn,
    )
    add(
        "credential-material",
        request,
        lambda d: d.__setitem__("api" + "_token", "placeholder"),
        validate_request_fn,
    )
    add(
        "foreign-account",
        request,
        lambda d: d.update(
            endpointRef="mcp://example.test/accounts/foreign/providers/anthropic/tools/claude"
        ),
        validate_request_fn,
    )
    add(
        "reusable-grant",
        request,
        lambda d: d["authority"].update(singleUse=False),
        validate_request_fn,
    )
    add(
        "bool-limit-smuggling",
        request,
        lambda d: d["limits"].update(timeoutSeconds=True),
        validate_request_fn,
    )
    add(
        "string-limit-type",
        request,
        lambda d: d["limits"].update(maxArtifacts="8"),
        validate_request_fn,
    )
    add(
        "inline-secret-value",
        request,
        lambda d: d["task"].update(promptRef="artifact://example.test/sk-" + "a" * 24 + "/r1"),
        validate_request_fn,
    )
    add(
        "receipt-handle",
        receipt,
        lambda d: d.update(email="operator@example.test"),
        validate_receipt_fn,
    )
    add(
        "inline-output",
        receipt,
        lambda d: d.update(outputInline="model output"),
        validate_receipt_fn,
    )
    add(
        "executed-without-artifact",
        receipt,
        lambda d: d.update(artifactRefs=[]),
        validate_receipt_fn,
    )
    cases.append(
        ("duplicate-json-key", lambda: strict_loads('{"operation":"inspect","operation":"invoke"}'))
    )
    cases.append(
        ("open-schema-in-list", lambda: assert_closed_schema({"oneOf": [{"type": "object"}]}))
    )
    return cases
