#!/usr/bin/env python3
"""Dependency-free conformance checks for account-runtime and service-access v1."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    from standard import account_fixtures as _fx
    from standard import account_primitives as _pr
    from standard import service_access_conformance as _sa
except ImportError:
    import account_fixtures as _fx  # type: ignore[no-redef]
    import account_primitives as _pr  # type: ignore[no-redef]
    import service_access_conformance as _sa  # type: ignore[no-redef]

ContractError, canonical, digest = _pr.ContractError, _pr.canonical, _pr.digest
exact, bounded_datetime = _pr.exact, _pr.bounded_datetime
bounded_list, unique_list = _pr.bounded_list, _pr.unique_list
reject_sensitive_keys, str_choice = _pr.reject_sensitive_keys, _pr.str_choice
RECEIPT_OUTCOMES = _pr.RECEIPT_OUTCOMES
SCHEMA_URI = _fx.SCHEMA_URI
graph_example, runtime_example = _fx.graph_example, _fx.runtime_example
request_example, receipt_example = _fx.request_example, _fx.receipt_example
ServiceAccessContracts = _sa.ServiceAccessContracts
validate_service_access = _sa.validate_service_access
validate_observation_freshness = _pr.validate_observation_freshness

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "account-runtime.schema.json"
GRAMMAR_PATH = ROOT / "account-runtime.v1.gbnf"
SCHEMA_DIGEST = "8abc84eaf6e04fd2c2469bf0b5dbc5682cc450c58a3554c373b177627f0130e6"
GRAMMAR_DIGEST = "11cd4b8308115d5f6926700c093e6c1dab0d511070777e233adfac99e7d92b74"

STORE_REF_RE = re.compile(r"\Astore://[a-z0-9.-]+/[A-Za-z0-9._:/-]+\Z")
SOURCE_REF_RE = re.compile(r"\A(?:store|profile|probe)://[a-z0-9.-]+/[A-Za-z0-9._:/-]+\Z")
VOLUME_REF_RE = re.compile(r"\Avolume://[a-z0-9.-]+/[A-Za-z0-9._:-]+\Z")
KVM_CONNECTOR_RE = re.compile(r"\Aconnector://[a-z0-9.-]+/[A-Za-z0-9._:/-]+/v[1-9][0-9]*\Z")
SERVICE_CLASSES = frozenset({"provider", "tool", "generic-service", "unknown"})
EVIDENCE_KINDS = frozenset(
    {
        "browser-login-origin",
        "browser-session-marker",
        "cli-profile-marker",
        "provider-verification",
        "operator-review",
    }
)
LINK_RELATIONS = frozenset(
    {"credential_observed", "session_observed", "account_inferred", "account_verified"}
)
LINK_CONFIDENCE = frozenset({"observed", "inferred", "verified"})
HOST_EXPOSURES = frozenset({"localhost-only", "authenticated-private-ingress"})
CLIPBOARDS = frozenset({"disabled", "brokered-text-only"})
INSTALL_STATES = frozenset({"missing", "installed_unverified", "available"})
AUTH_STATES = frozenset(
    {"missing", "profile_present", "available_auth_unverified", "verified", "expired", "revoked"}
)
ENDPOINT_STATES = frozenset({"unreachable", "reachable_unverified", "verified"})
PROJECT_STATES = frozenset({"unmounted", "mounted_read_only", "mounted_read_write"})
READINESS_STATES = frozenset(
    {"initialization_required", "session_unverified", "ready", "degraded", "revoked"}
)
CONTROL_OPS = frozenset({"inspect", "plan", "invoke", "cancel", "focus", "close"})


def _match_bounded_uri(value: Any, pattern: re.Pattern[str], max_len: int, label: str) -> str:
    if not isinstance(value, str) or len(value) > max_len or pattern.fullmatch(value) is None:
        raise ContractError(f"invalid {label}")
    return _pr.validate_safe_uri_segments(value, f"invalid {label}")


class Contracts:
    def __init__(self) -> None:
        self.schema = _pr.load_strict_json(SCHEMA_PATH)
        self.grammar = _pr.read_regular_utf8(GRAMMAR_PATH)
        defs = self.schema.get("$defs", {})
        names = (
            "identifier",
            "sha256",
            "sha256Ref",
            "identityRef",
            "serviceRef",
            "providerRef",
            "toolRef",
            "runtimeRef",
            "projectRef",
            "containerRef",
            "mcpEndpointRef",
            "evidenceRef",
            "artifactRef",
            "schemaRef",
            "vaultRef",
            "intentRef",
            "grantRef",
            "origin",
        )
        self.patterns = {
            name: _pr.compile_anchored_pattern(defs[name]["pattern"]) for name in names
        }
        self.max_lengths: dict[str, int | None] = {
            name: defs[name].get("maxLength") for name in names
        }

    def ref(self, name: str, value: Any) -> str:
        max_len = self.max_lengths[name]
        if (
            not isinstance(value, str)
            or (max_len is not None and len(value) > max_len)
            or self.patterns[name].fullmatch(value) is None
        ):
            raise ContractError(f"invalid {name}")
        return _pr.validate_safe_uri_segments(value, f"invalid {name}")

    def integrity(self) -> None:
        if self.schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ContractError("unexpected schema dialect")
        if self.schema.get("$id") != SCHEMA_URI:
            raise ContractError("unexpected schema identifier")
        if digest(canonical(self.schema)) != SCHEMA_DIGEST:
            raise ContractError("schema digest mismatch")
        if digest(self.grammar) != GRAMMAR_DIGEST:
            raise ContractError("grammar digest mismatch")
        variants = {
            item.get("$ref")
            for item in self.schema.get("oneOf", [])
            if isinstance(item, dict) and isinstance(item.get("$ref"), str)
        }
        expected_variants = {
            "#/$defs/graph",
            "#/$defs/runtimeBinding",
            "#/$defs/request",
            "#/$defs/receipt",
        }
        if variants != expected_variants:
            raise ContractError("document variants incomplete")
        fragments = (
            "root ::= request",
            "raw shell",
            "external-exact-grant",
            "mcp-ref ::=",
            "artifact-ref ::=",
        )
        if any(fragment not in self.grammar for fragment in fragments):
            raise ContractError("grammar is incomplete")
        _pr.assert_closed_schema(self.schema, "object schema is not closed")


def validate_graph(c: Contracts, value: Any) -> None:
    _pr.reject_secret_material(value)
    keys = {
        "$schema",
        "schema",
        "snapshotId",
        "observedAt",
        "identities",
        "services",
        "links",
        "evidence",
    }
    value = exact(value, keys)
    if value["$schema"] != SCHEMA_URI or value["schema"] != "wellmanifest.account-graph/v1":
        raise ContractError("unsupported graph schema")
    c.ref("identifier", value["snapshotId"])
    bounded_datetime(value["observedAt"])
    identities: set[str] = set()
    services: set[str] = set()
    evidence: set[str] = set()

    for item in bounded_list(value["identities"], "GRAPH-001", minimum=1, maximum=100000):
        item = exact(item, {"ref", "handle", "storeRefs", "active"})
        ref = c.ref("identityRef", item["ref"])
        if ref in identities:
            raise ContractError("duplicate identity")
        identities.add(ref)
        _pr.strict_bool(item["active"], "active")
        handle = exact(item["handle"], {"kind", "value", "classification"})
        val = handle["value"]
        if (
            handle["kind"] != "email"
            or handle["classification"] != "restricted"
            or not isinstance(val, str)
            or len(val) > 254
            or _pr.EMAIL_RE.fullmatch(val) is None
        ):
            raise ContractError("invalid account handle")
        for sr in unique_list(item["storeRefs"], "GRAPH-001", minimum=1, maximum=32):
            _match_bounded_uri(sr, STORE_REF_RE, 240, "storeRef")

    for item in bounded_list(value["services"], "GRAPH-001", minimum=1, maximum=100000):
        item = exact(item, {"ref", "name", "origins", "classification"}, {"providerRef"})
        ref = c.ref("serviceRef", item["ref"])
        if ref in services:
            raise ContractError("duplicate service")
        services.add(ref)
        sname = item["name"]
        if (
            not isinstance(sname, str)
            or not sname.strip()
            or len(sname) > 160
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in sname)
        ):
            raise ContractError("invalid service name")
        str_choice(item["classification"], SERVICE_CLASSES, "invalid service classification")
        for origin in unique_list(item["origins"], "GRAPH-001", minimum=1, maximum=32):
            c.ref("origin", origin)
        if "providerRef" in item:
            c.ref("providerRef", item["providerRef"])

    for item in bounded_list(value["evidence"], "GRAPH-001", minimum=1, maximum=1000000):
        ev_keys = {
            "ref",
            "kind",
            "sourceRef",
            "digest",
            "collectedAt",
            "secretsDiscarded",
            "valuesPersisted",
        }
        item = exact(item, ev_keys)
        ref = c.ref("evidenceRef", item["ref"])
        if ref in evidence:
            raise ContractError("duplicate evidence")
        evidence.add(ref)
        str_choice(item["kind"], EVIDENCE_KINDS, "invalid evidence kind")
        _match_bounded_uri(item["sourceRef"], SOURCE_REF_RE, 320, "sourceRef")
        c.ref("sha256Ref", item["digest"])
        bounded_datetime(item["collectedAt"])
        if item["secretsDiscarded"] is not True or item["valuesPersisted"] is not False:
            raise ContractError("evidence retained secret values")

    for item in bounded_list(value["links"], "GRAPH-001", maximum=1000000):
        link_keys = {
            "identityRef",
            "serviceRef",
            "relation",
            "confidence",
            "evidenceRefs",
            "observedAt",
        }
        item = exact(item, link_keys, {"verifiedAt"})
        if (
            c.ref("identityRef", item["identityRef"]) not in identities
            or c.ref("serviceRef", item["serviceRef"]) not in services
        ):
            raise ContractError("link target absent")
        relation = str_choice(item["relation"], LINK_RELATIONS, "invalid link relation")
        confidence = str_choice(item["confidence"], LINK_CONFIDENCE, "invalid link confidence")
        ev_refs = unique_list(item["evidenceRefs"], "GRAPH-001", minimum=1, maximum=32)
        if any(c.ref("evidenceRef", ref) not in evidence for ref in ev_refs):
            raise ContractError("link evidence absent")
        bounded_datetime(item["observedAt"])
        if "verifiedAt" in item:
            bounded_datetime(item["verifiedAt"])
        if relation == "account_verified" and (
            confidence != "verified" or "verifiedAt" not in item
        ):
            raise ContractError("verified link lacks proof")


def validate_runtime(c: Contracts, value: Any) -> None:
    _pr.reject_secret_material(value)
    keys = {
        "$schema",
        "schema",
        "runtimeRef",
        "graphDigest",
        "identityRef",
        "providerRef",
        "toolRef",
        "projectRef",
        "containerRef",
        "mcpEndpointRef",
        "persistence",
        "state",
        "control",
        "secretResolution",
    }
    value = exact(value, keys)
    if (
        value["$schema"] != SCHEMA_URI
        or value["schema"] != "wellmanifest.account-runtime-binding/v1"
    ):
        raise ContractError("unsupported runtime schema")
    for name in (
        "runtimeRef",
        "identityRef",
        "providerRef",
        "toolRef",
        "projectRef",
        "containerRef",
        "mcpEndpointRef",
    ):
        c.ref(name, value[name])
    c.ref("sha256Ref", value["graphDigest"])
    p_keys = {
        "profileVolumeRef",
        "projectMountRef",
        "restartPolicy",
        "sessionRecovery",
        "profileIsolation",
        "hostExposure",
        "clipboard",
    }
    p = exact(value["persistence"], p_keys)
    _match_bounded_uri(p["profileVolumeRef"], VOLUME_REF_RE, 240, "profileVolumeRef")
    c.ref("projectRef", p["projectMountRef"])
    if (
        p["restartPolicy"] != "unless-stopped"
        or p["sessionRecovery"] != "verify-after-restart"
        or p["profileIsolation"] != "per-account"
    ):
        raise ContractError("unsafe persistence policy")
    str_choice(p["hostExposure"], HOST_EXPOSURES, "invalid hostExposure")
    str_choice(p["clipboard"], CLIPBOARDS, "invalid clipboard policy")
    if p["projectMountRef"] != value["projectRef"]:
        raise ContractError("project mount mismatch")
    st_keys = {"installation", "authentication", "endpoint", "project", "readiness", "observedAt"}
    state = exact(value["state"], st_keys)
    str_choice(state["installation"], INSTALL_STATES, "invalid installation state")
    str_choice(state["authentication"], AUTH_STATES, "invalid authentication state")
    str_choice(state["endpoint"], ENDPOINT_STATES, "invalid endpoint state")
    str_choice(state["project"], PROJECT_STATES, "invalid project state")
    str_choice(state["readiness"], READINESS_STATES, "invalid readiness state")
    bounded_datetime(state["observedAt"])
    ready = (
        state["installation"] == "available"
        and state["authentication"] == "verified"
        and state["endpoint"] == "verified"
        and state["project"] in {"mounted_read_only", "mounted_read_write"}
    )
    if (state["readiness"] == "ready") != ready:
        raise ContractError("readiness contradicts probes")
    ctrl_keys = {
        "operations",
        "rawShell",
        "arbitraryArgv",
        "mcpSchemaRequired",
        "gbnfRequired",
        "humanVisible",
    }
    control = exact(value["control"], ctrl_keys, {"kvmConnectorRef"})
    for op in unique_list(control["operations"], "RUNTIME-001", minimum=1, maximum=8):
        str_choice(op, CONTROL_OPS, "unsupported control operation")
    if (
        control["rawShell"] is not False
        or control["arbitraryArgv"] is not False
        or control["mcpSchemaRequired"] is not True
        or control["gbnfRequired"] is not True
        or control["humanVisible"] is not True
    ):
        raise ContractError("unsafe control surface")
    if "kvmConnectorRef" in control:
        _match_bounded_uri(control["kvmConnectorRef"], KVM_CONNECTOR_RE, 320, "kvmConnectorRef")
    secret = exact(value["secretResolution"], {"mode", "valuesInDocument", "refs"})
    if secret["mode"] != "runtime-vault" or secret["valuesInDocument"] is not False:
        raise ContractError("unsafe secret resolution")
    for ref in unique_list(secret["refs"], "RUNTIME-001", minimum=1, maximum=32):
        c.ref("vaultRef", ref)


def validate_request(c: Contracts, value: Any) -> None:
    _pr.validate_request(c, value, SCHEMA_URI)


def validate_receipt(c: Contracts, value: Any) -> None:
    _pr.validate_receipt(c, value, SCHEMA_URI)


def validate_document(value: Any) -> None:
    if not isinstance(value, dict):
        raise ContractError("document must be an object")
    schema = value.get("schema")
    if not isinstance(schema, str):
        raise ContractError("unsupported document schema")
    if schema == "wellmanifest.service-access-catalog/v1":
        service = ServiceAccessContracts()
        service.integrity()
        validate_service_access(service, value)
        return
    c = Contracts()
    c.integrity()
    validators: dict[str, Callable[[Contracts, Any], None]] = {
        "wellmanifest.account-graph/v1": validate_graph,
        "wellmanifest.account-runtime-binding/v1": validate_runtime,
        "wellmanifest.account-runtime-request/v1": validate_request,
        "wellmanifest.account-runtime-receipt/v1": validate_receipt,
    }
    validator = validators.get(schema)
    if validator is None:
        raise ContractError("unsupported document schema")
    validator(c, value)


def run_all() -> dict[str, Any]:
    c = Contracts()
    c.integrity()
    validate_graph(c, graph_example())
    validate_runtime(c, runtime_example())
    validate_request(c, request_example())
    validate_receipt(c, receipt_example())

    cases = _fx.build_adversarial_account_cases(
        validate_graph_fn=lambda d: validate_graph(c, d),
        validate_runtime_fn=lambda d: validate_runtime(c, d),
        validate_request_fn=lambda d: validate_request(c, d),
        validate_receipt_fn=lambda d: validate_receipt(c, d),
    )
    rejected: list[str] = []
    for name, case in cases:
        try:
            case()
        except ContractError:
            rejected.append(name)
        else:
            raise AssertionError(f"adversarial case accepted: {name}")

    return {
        "schema": "wellmanifest.account-runtime-conformance/v1",
        "ok": True,
        "schemaDigest": "sha256:" + SCHEMA_DIGEST,
        "grammarDigest": "sha256:" + GRAMMAR_DIGEST,
        "positiveVariants": 5,
        "adversarialRejected": rejected,
        "observationFreshness": _pr.verify_observation_freshness_suite(),
        "serviceAccess": _sa.run_service_access_conformance(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--file", type=Path)
    args = parser.parse_args()
    try:
        if args.all:
            print(json.dumps(run_all(), indent=2, sort_keys=True, allow_nan=False))
        elif args.file:
            validate_document(_pr.load_strict_json(args.file))
            print(f"PASS: {args.file}")
        else:
            parser.error("choose --all or --file")
    except (ContractError, json.JSONDecodeError, OSError) as error:
        print(f"FAIL: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
