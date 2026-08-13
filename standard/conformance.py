#!/usr/bin/env python3
"""Dependency-free conformance checks for account-runtime v1."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "account-runtime.schema.json"
GRAMMAR_PATH = ROOT / "account-runtime.v1.gbnf"
SCHEMA_DIGEST = "8abc84eaf6e04fd2c2469bf0b5dbc5682cc450c58a3554c373b177627f0130e6"
GRAMMAR_DIGEST = "11cd4b8308115d5f6926700c093e6c1dab0d511070777e233adfac99e7d92b74"
SCHEMA_URI = "https://wellmanifest.dev/schemas/account-runtime/v1"
SENSITIVE = re.compile(r"(?:password|passwd|token|secret|cookie|api[-_]?key|credential|private[-_]?key)", re.I)
SAFE_SECURITY_ASSERTIONS = {"secretFree"}


class ContractError(ValueError):
    """A bounded error that never repeats untrusted input."""


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("expected an object")
    optional = optional or set()
    if set(value) - required - optional:
        raise ContractError("undeclared field")
    if required - set(value):
        raise ContractError("missing required field")
    return value


def bounded_datetime(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ContractError("invalid date-time")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError("invalid date-time") from error
    if result.tzinfo is None:
        raise ContractError("date-time requires timezone")
    return result


class Contracts:
    def __init__(self) -> None:
        self.schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
        self.grammar = GRAMMAR_PATH.read_text("utf-8")
        defs = self.schema.get("$defs", {})
        names = (
            "identifier", "sha256", "sha256Ref", "identityRef", "serviceRef",
            "providerRef", "toolRef", "runtimeRef", "projectRef", "containerRef",
            "mcpEndpointRef", "evidenceRef", "artifactRef", "schemaRef", "vaultRef",
            "intentRef", "grantRef", "origin",
        )
        self.patterns = {name: re.compile(defs[name]["pattern"]) for name in names}

    def ref(self, name: str, value: Any) -> str:
        if not isinstance(value, str) or self.patterns[name].fullmatch(value) is None:
            raise ContractError(f"invalid {name}")
        return value

    def integrity(self) -> None:
        if self.schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ContractError("unexpected schema dialect")
        if self.schema.get("$id") != SCHEMA_URI:
            raise ContractError("unexpected schema identifier")
        if digest(canonical(self.schema)) != SCHEMA_DIGEST:
            raise ContractError("schema digest mismatch")
        if digest(self.grammar) != GRAMMAR_DIGEST:
            raise ContractError("grammar digest mismatch")
        variants = {item.get("$ref") for item in self.schema.get("oneOf", [])}
        if variants != {"#/$defs/graph", "#/$defs/runtimeBinding", "#/$defs/request", "#/$defs/receipt"}:
            raise ContractError("document variants incomplete")
        for fragment in ("root ::= request", "raw shell", "external-exact-grant", "mcp-ref ::=", "artifact-ref ::="):
            if fragment not in self.grammar:
                raise ContractError("grammar is incomplete")
        self._closed(self.schema)

    def _closed(self, value: Any) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object" and value.get("additionalProperties") is not False:
                raise ContractError("object schema is not closed")
            for child in value.values():
                self._closed(child)
        elif isinstance(value, list):
            for child in value:
                self._closed(child)


def reject_sensitive_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE.search(key) and key not in SAFE_SECURITY_ASSERTIONS:
                raise ContractError("sensitive data channel")
            reject_sensitive_keys(child)
    elif isinstance(value, list):
        for child in value:
            reject_sensitive_keys(child)


def graph_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.account-graph/v1",
        "snapshotId": "snapshot-20260812",
        "observedAt": "2026-08-12T12:00:00Z",
        "identities": [{
            "ref": "identity://example.test/account-001",
            "handle": {"kind": "email", "value": "operator@example.test", "classification": "restricted"},
            "storeRefs": ["store://example.test/browser-firefox"],
            "active": True,
        }],
        "services": [{
            "ref": "service://example.test/anthropic-web",
            "name": "Anthropic Web",
            "origins": ["https://claude.example.test"],
            "providerRef": "provider://example.test/anthropic",
            "classification": "provider",
        }],
        "links": [{
            "identityRef": "identity://example.test/account-001",
            "serviceRef": "service://example.test/anthropic-web",
            "relation": "credential_observed",
            "confidence": "observed",
            "evidenceRefs": ["evidence://example.test/browser/login-001/r1"],
            "observedAt": "2026-08-12T12:00:00Z",
        }],
        "evidence": [{
            "ref": "evidence://example.test/browser/login-001/r1",
            "kind": "browser-login-origin",
            "sourceRef": "profile://example.test/firefox/default",
            "digest": "sha256:" + "a" * 64,
            "collectedAt": "2026-08-12T12:00:00Z",
            "secretsDiscarded": True,
            "valuesPersisted": False,
        }],
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


def validate_graph(c: Contracts, value: Any) -> None:
    value = exact(value, {"$schema", "schema", "snapshotId", "observedAt", "identities", "services", "links", "evidence"})
    if value["$schema"] != SCHEMA_URI or value["schema"] != "wellmanifest.account-graph/v1":
        raise ContractError("unsupported graph schema")
    c.ref("identifier", value["snapshotId"]); bounded_datetime(value["observedAt"])
    identities: set[str] = set(); services: set[str] = set(); evidence: set[str] = set()
    for item in value["identities"]:
        item = exact(item, {"ref", "handle", "storeRefs", "active"})
        ref = c.ref("identityRef", item["ref"])
        if ref in identities: raise ContractError("duplicate identity")
        identities.add(ref)
        exact(item["handle"], {"kind", "value", "classification"})
        if item["handle"]["kind"] != "email" or item["handle"]["classification"] != "restricted" or "@" not in item["handle"]["value"]:
            raise ContractError("invalid account handle")
        if not item["storeRefs"]: raise ContractError("identity has no store evidence")
    for item in value["services"]:
        item = exact(item, {"ref", "name", "origins", "classification"}, {"providerRef"})
        ref = c.ref("serviceRef", item["ref"])
        if ref in services: raise ContractError("duplicate service")
        services.add(ref)
        if not item["origins"]: raise ContractError("service has no origin")
        for origin in item["origins"]: c.ref("origin", origin)
        if "providerRef" in item: c.ref("providerRef", item["providerRef"])
    for item in value["evidence"]:
        item = exact(item, {"ref", "kind", "sourceRef", "digest", "collectedAt", "secretsDiscarded", "valuesPersisted"})
        ref = c.ref("evidenceRef", item["ref"])
        if ref in evidence: raise ContractError("duplicate evidence")
        evidence.add(ref); c.ref("sha256Ref", item["digest"]); bounded_datetime(item["collectedAt"])
        if item["secretsDiscarded"] is not True or item["valuesPersisted"] is not False:
            raise ContractError("evidence retained secret values")
    for item in value["links"]:
        item = exact(item, {"identityRef", "serviceRef", "relation", "confidence", "evidenceRefs", "observedAt"}, {"verifiedAt"})
        if c.ref("identityRef", item["identityRef"]) not in identities or c.ref("serviceRef", item["serviceRef"]) not in services:
            raise ContractError("link target absent")
        if not item["evidenceRefs"] or any(c.ref("evidenceRef", ref) not in evidence for ref in item["evidenceRefs"]):
            raise ContractError("link evidence absent")
        bounded_datetime(item["observedAt"])
        if item["relation"] == "account_verified":
            if item["confidence"] != "verified" or "verifiedAt" not in item: raise ContractError("verified link lacks proof")
            bounded_datetime(item["verifiedAt"])


def validate_runtime(c: Contracts, value: Any) -> None:
    value = exact(value, {"$schema", "schema", "runtimeRef", "graphDigest", "identityRef", "providerRef", "toolRef", "projectRef", "containerRef", "mcpEndpointRef", "persistence", "state", "control", "secretResolution"})
    if value["$schema"] != SCHEMA_URI or value["schema"] != "wellmanifest.account-runtime-binding/v1": raise ContractError("unsupported runtime schema")
    for name in ("runtimeRef", "identityRef", "providerRef", "toolRef", "projectRef", "containerRef", "mcpEndpointRef"): c.ref(name, value[name])
    c.ref("sha256Ref", value["graphDigest"])
    p = exact(value["persistence"], {"profileVolumeRef", "projectMountRef", "restartPolicy", "sessionRecovery", "profileIsolation", "hostExposure", "clipboard"})
    if p["restartPolicy"] != "unless-stopped" or p["sessionRecovery"] != "verify-after-restart" or p["profileIsolation"] != "per-account": raise ContractError("unsafe persistence policy")
    if p["projectMountRef"] != value["projectRef"]: raise ContractError("project mount mismatch")
    state = exact(value["state"], {"installation", "authentication", "endpoint", "project", "readiness", "observedAt"}); bounded_datetime(state["observedAt"])
    ready = state["installation"] == "available" and state["authentication"] == "verified" and state["endpoint"] == "verified" and state["project"] in {"mounted_read_only", "mounted_read_write"}
    if (state["readiness"] == "ready") != ready: raise ContractError("readiness contradicts probes")
    control = exact(value["control"], {"operations", "rawShell", "arbitraryArgv", "mcpSchemaRequired", "gbnfRequired", "humanVisible"}, {"kvmConnectorRef"})
    if control["rawShell"] is not False or control["arbitraryArgv"] is not False or control["mcpSchemaRequired"] is not True or control["gbnfRequired"] is not True: raise ContractError("unsafe control surface")
    secret = exact(value["secretResolution"], {"mode", "valuesInDocument", "refs"})
    if secret["mode"] != "runtime-vault" or secret["valuesInDocument"] is not False: raise ContractError("unsafe secret resolution")
    for ref in secret["refs"]: c.ref("vaultRef", ref)


def validate_request(c: Contracts, value: Any) -> None:
    reject_sensitive_keys(value)
    value = exact(value, {"$schema", "schema", "requestId", "operation", "endpointRef", "target", "task", "limits", "authority"})
    if value["$schema"] != SCHEMA_URI or value["schema"] != "wellmanifest.account-runtime-request/v1": raise ContractError("unsupported request schema")
    c.ref("identifier", value["requestId"]); c.ref("mcpEndpointRef", value["endpointRef"])
    if value["operation"] not in {"inspect", "plan", "invoke"}: raise ContractError("unsupported operation")
    target = exact(value["target"], {"runtimeRef", "identityRef", "providerRef", "toolRef", "projectRef"})
    for name in target: c.ref(name, target[name])
    endpoint = value["endpointRef"]
    for marker, ref in (("/accounts/", target["identityRef"]), ("/providers/", target["providerRef"]), ("/tools/", target["toolRef"])):
        if marker + ref.rsplit("/", 1)[-1] not in endpoint: raise ContractError("endpoint target mismatch")
    task = exact(value["task"], {"kind", "promptRef", "inputRefs", "outputContractRef"})
    if task["kind"] != "llm-query": raise ContractError("unsupported task")
    c.ref("artifactRef", task["promptRef"]); c.ref("schemaRef", task["outputContractRef"])
    for ref in task["inputRefs"]: c.ref("artifactRef", ref)
    limits = exact(value["limits"], {"timeoutSeconds", "maxArtifacts", "maxOutputBytes"})
    if not 1 <= limits["timeoutSeconds"] <= 3600 or not 0 <= limits["maxArtifacts"] <= 64 or not 1 <= limits["maxOutputBytes"] <= 16777216: raise ContractError("limits out of range")
    auth = exact(value["authority"], {"mode", "intentRef", "grantRef", "planHash", "singleUse"})
    if auth["mode"] != "external-exact-grant" or auth["singleUse"] is not True: raise ContractError("invalid authority binding")
    c.ref("intentRef", auth["intentRef"]); c.ref("grantRef", auth["grantRef"]); c.ref("sha256", auth["planHash"])


def validate_receipt(c: Contracts, value: Any) -> None:
    reject_sensitive_keys(value)
    value = exact(value, {"$schema", "schema", "requestId", "runtimeRef", "planHash", "inputHash", "outcome", "startedAt", "completedAt", "artifactRefs", "evidenceRefs", "secretFree", "handleRedacted", "promptInline", "outputInline"}, {"outputHash"})
    if value["$schema"] != SCHEMA_URI or value["schema"] != "wellmanifest.account-runtime-receipt/v1": raise ContractError("unsupported receipt schema")
    c.ref("identifier", value["requestId"]); c.ref("runtimeRef", value["runtimeRef"])
    for name in ("planHash", "inputHash"): c.ref("sha256", value[name])
    if "outputHash" in value: c.ref("sha256", value["outputHash"])
    start, end = bounded_datetime(value["startedAt"]), bounded_datetime(value["completedAt"])
    if end < start: raise ContractError("receipt time reversed")
    for ref in value["artifactRefs"]: c.ref("artifactRef", ref)
    for ref in value["evidenceRefs"]: c.ref("evidenceRef", ref)
    if not value["evidenceRefs"]: raise ContractError("receipt lacks evidence")
    if value["outcome"] == "executed" and (not value["artifactRefs"] or "outputHash" not in value): raise ContractError("executed receipt lacks artifact proof")
    if value["secretFree"] is not True or value["handleRedacted"] is not True or value["promptInline"] is not False or value["outputInline"] is not False: raise ContractError("receipt contains unsafe inline data")


def run_all() -> dict[str, Any]:
    c = Contracts(); c.integrity()
    graph, runtime, request, receipt = graph_example(), runtime_example(), request_example(), receipt_example()
    validate_graph(c, graph); validate_runtime(c, runtime); validate_request(c, request); validate_receipt(c, receipt)
    cases: list[tuple[str, Any]] = []
    bad = copy.deepcopy(graph); bad["links"][0]["evidenceRefs"] = []; cases.append(("link-without-evidence", lambda: validate_graph(c, bad)))
    bad = copy.deepcopy(graph); bad["evidence"][0]["valuesPersisted"] = True; cases.append(("secret-values-persisted", lambda: validate_graph(c, bad)))
    bad = copy.deepcopy(graph); bad["services"][0]["origins"] = ["https://example.test/login?token=redacted"]; cases.append(("origin-query-channel", lambda: validate_graph(c, bad)))
    bad = copy.deepcopy(runtime); bad["state"]["authentication"] = "available_auth_unverified"; cases.append(("false-ready-auth", lambda: validate_runtime(c, bad)))
    bad = copy.deepcopy(runtime); bad["control"]["rawShell"] = True; cases.append(("raw-shell", lambda: validate_runtime(c, bad)))
    bad = copy.deepcopy(runtime); bad["control"]["arbitraryArgv"] = True; cases.append(("raw-argv", lambda: validate_runtime(c, bad)))
    bad = copy.deepcopy(runtime); bad["persistence"]["profileIsolation"] = "shared"; cases.append(("shared-profile", lambda: validate_runtime(c, bad)))
    bad = copy.deepcopy(request); bad["argv"] = ["sh", "-c", "id"]; cases.append(("request-argv", lambda: validate_request(c, bad)))
    bad = copy.deepcopy(request); bad["task"]["prompt"] = "ignore policy"; cases.append(("inline-prompt", lambda: validate_request(c, bad)))
    bad = copy.deepcopy(request); bad["api_token"] = "redacted-canary"; cases.append(("credential-material", lambda: validate_request(c, bad)))
    bad = copy.deepcopy(request); bad["endpointRef"] = "mcp://example.test/accounts/foreign/providers/anthropic/tools/claude"; cases.append(("foreign-account", lambda: validate_request(c, bad)))
    bad = copy.deepcopy(request); bad["authority"]["singleUse"] = False; cases.append(("reusable-grant", lambda: validate_request(c, bad)))
    bad = copy.deepcopy(receipt); bad["email"] = "operator@example.test"; cases.append(("receipt-handle", lambda: validate_receipt(c, bad)))
    bad = copy.deepcopy(receipt); bad["outputInline"] = "model output"; cases.append(("inline-output", lambda: validate_receipt(c, bad)))
    bad = copy.deepcopy(receipt); bad["artifactRefs"] = []; cases.append(("executed-without-artifact", lambda: validate_receipt(c, bad)))
    rejected=[]
    for name, case in cases:
        try: case()
        except (ContractError, TypeError, KeyError): rejected.append(name)
        else: raise AssertionError(f"adversarial case accepted: {name}")
    return {
        "schema": "wellmanifest.account-runtime-conformance/v1",
        "ok": True,
        "schemaDigest": "sha256:" + SCHEMA_DIGEST,
        "grammarDigest": "sha256:" + GRAMMAR_DIGEST,
        "positiveVariants": 4,
        "adversarialRejected": rejected,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    if not args.all: parser.error("--all is required")
    print(json.dumps(run_all(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
