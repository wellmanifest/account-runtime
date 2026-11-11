#!/usr/bin/env python3
"""Shared deterministic validation primitives for account-runtime and service-access v1."""

from __future__ import annotations

import math
import re
import time
from datetime import UTC, datetime
from typing import Any

try:
    from standard import account_io as _io
except ImportError:
    import account_io as _io  # type: ignore[no-redef]

MAX_INPUT_BYTES = _io.MAX_INPUT_BYTES
MAX_JSON_DEPTH = _io.MAX_JSON_DEPTH
MAX_JSON_INT_DIGITS = _io.MAX_JSON_INT_DIGITS
SENSITIVE_KEY = _io.SENSITIVE_KEY
SAFE_SECURITY_ASSERTIONS = _io.SAFE_SECURITY_ASSERTIONS
SECRET_MATERIAL = _io.SECRET_MATERIAL
ContractError = _io.ContractError
_check_utf8_str = _io._check_utf8_str
_check_json_depth = _io._check_json_depth
read_regular_utf8 = _io.read_regular_utf8
strict_loads = _io.strict_loads
load_strict_json = _io.load_strict_json
canonical = _io.canonical
digest = _io.digest
reject_sensitive_keys = _io.reject_sensitive_keys
reject_secret_material = _io.reject_secret_material

__all__ = [
    "ContractError",
    "EMAIL_RE",
    "MAX_INPUT_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_JSON_INT_DIGITS",
    "RECEIPT_OUTCOMES",
    "RFC3339_DT",
    "SAFE_SECURITY_ASSERTIONS",
    "SECRET_MATERIAL",
    "SENSITIVE_KEY",
    "_check_json_depth",
    "_check_utf8_str",
    "assert_closed_schema",
    "bounded_datetime",
    "bounded_int",
    "bounded_list",
    "canonical",
    "compile_anchored_pattern",
    "digest",
    "exact",
    "load_strict_json",
    "read_regular_utf8",
    "reject_secret_material",
    "reject_sensitive_keys",
    "str_choice",
    "strict_bool",
    "strict_loads",
    "unique_list",
    "validate_observation_freshness",
    "validate_receipt",
    "validate_request",
    "validate_safe_uri_segments",
    "verify_observation_freshness_suite",
]

RFC3339_DT = re.compile(
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z"
)
EMAIL_RE = re.compile(
    r"\A(?!.*\.\.)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z"
)
RECEIPT_OUTCOMES = frozenset(
    {
        "denied",
        "initialization_required",
        "auth_unverified",
        "executed",
        "executed_unverified",
        "failed",
        "cancelled",
    }
)


def compile_anchored_pattern(raw: str) -> re.Pattern[str]:
    if not isinstance(raw, str) or not raw:
        raise ContractError("invalid regex pattern")
    body = raw[1:] if raw.startswith("^") else raw
    if body.endswith("$") and not body.endswith(r"\$"):
        body = body[:-1]
    return re.compile(rf"\A(?:{body})\Z")


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise ContractError("expected an object")
    optional_keys = optional or set()
    if set(value) - required - optional_keys:
        raise ContractError("undeclared field")
    if required - set(value):
        raise ContractError("missing required field")
    return value


def str_choice(value: Any, allowed: set[str] | frozenset[str], message: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ContractError(message)
    return value


def validate_safe_uri_segments(uri: str, message: str = "unsafe URI path segment") -> str:
    if (
        not isinstance(uri, str)
        or not uri
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in uri)
        or any(ch in uri for ch in ("\\", "?", "#"))
    ):
        raise ContractError(message)
    if "://" in uri:
        rest = uri.partition("://")[2]
        if (
            not rest
            or rest[0] in {"/", ":"}
            or rest[-1] in {"/", ":"}
            or "//" in rest
            or "::" in rest
        ):
            raise ContractError(message)
        authority, slash, path = rest.partition("/")
        host, port_sep, port = authority.partition(":")
        if (
            not host
            or host in {".", ".."}
            or host.startswith(".")
            or host.endswith(".")
            or ".." in host
        ):
            raise ContractError(message)
        if port_sep and (":" in port or not port.isdigit() or not 1 <= int(port) <= 65535):
            raise ContractError(message)
        if slash and (not path or any(seg in {"", ".", ".."} for seg in re.split(r"[/:]", path))):
            raise ContractError(message)
    elif ":" in uri and (
        uri[0] == ":"
        or uri[-1] == ":"
        or "::" in uri
        or any(seg in {"", ".", ".."} for seg in uri.split(":"))
    ):
        raise ContractError(message)
    return uri


def bounded_int(value: Any, minimum: int, maximum: int, label: str = "integer") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ContractError(f"invalid {label}")
    return value


def strict_bool(value: Any, label: str = "boolean") -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"invalid {label}")
    return value


def bounded_datetime(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40 or RFC3339_DT.fullmatch(value) is None:
        raise ContractError("invalid date-time")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError("invalid date-time") from error
    if result.tzinfo is None:
        raise ContractError("date-time requires timezone")
    return result


def bounded_list(
    value: Any, code: str = "DOC-001", *, minimum: int = 0, maximum: int | None = None
) -> list[Any]:
    if not isinstance(value, list) or len(value) < minimum:
        raise ContractError(f"{code}: expected a bounded list")
    if maximum is not None and len(value) > maximum:
        raise ContractError(f"{code}: list exceeds maximum length")
    return value


def unique_list(
    value: Any, code: str = "DOC-001", *, minimum: int = 0, maximum: int | None = None
) -> list[Any]:
    items = bounded_list(value, code, minimum=minimum, maximum=maximum)
    try:
        unique = len(set(items)) == len(items)
    except TypeError as error:
        raise ContractError(f"{code}: list contains a non-scalar value") from error
    if not unique:
        raise ContractError(f"{code}: duplicate list member")
    return items


def assert_closed_schema(node: Any, error_message: str = "object schema is not closed") -> None:
    map_keys = {"properties", "patternProperties", "$defs", "dependentSchemas"}
    predicate_keys = {"if", "not", "contains", "propertyNames"}
    overlay_keys = predicate_keys | {"then", "else", "allOf"}
    stack: list[tuple[Any, int, bool, bool]] = [(node, 0, False, False)]
    while stack:
        current, depth, is_map, in_overlay = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ContractError("schema nesting exceeds maximum depth")
        if isinstance(current, dict):
            is_explicit_obj = current.get("type") == "object"
            is_implicit_obj = not in_overlay and (
                "properties" in current or "patternProperties" in current
            )
            if (
                not is_map
                and (is_explicit_obj or is_implicit_obj)
                and current.get("additionalProperties") is not False
            ):
                raise ContractError(error_message)
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ContractError("schema object key must be a string")
                if not is_map and key in predicate_keys:
                    continue
                child_map = not is_map and key in map_keys
                child_overlay = in_overlay or (not is_map and key in overlay_keys)
                stack.append((child, depth + 1, child_map, child_overlay))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1, False, in_overlay))


def validate_request(c: Any, value: Any, schema_uri: str) -> None:
    reject_sensitive_keys(value)
    reject_secret_material(value)
    keys = {
        "$schema",
        "schema",
        "requestId",
        "operation",
        "endpointRef",
        "target",
        "task",
        "limits",
        "authority",
    }
    value = exact(value, keys)
    if (
        value["$schema"] != schema_uri
        or value["schema"] != "wellmanifest.account-runtime-request/v1"
    ):
        raise ContractError("unsupported request schema")
    c.ref("identifier", value["requestId"])
    endpoint = c.ref("mcpEndpointRef", value["endpointRef"])
    str_choice(value["operation"], {"inspect", "plan", "invoke"}, "unsupported operation")
    target = exact(
        value["target"], {"runtimeRef", "identityRef", "providerRef", "toolRef", "projectRef"}
    )
    for name in target:
        c.ref(name, target[name])
    acct_slug = target["identityRef"].rsplit("/", 1)[-1]
    prov_slug = target["providerRef"].rsplit("/", 1)[-1]
    tool_slug = target["toolRef"].rsplit("/", 1)[-1]
    expected_path = f"accounts/{acct_slug}/providers/{prov_slug}/tools/{tool_slug}"
    if endpoint.partition("://")[2].partition("/")[2] != expected_path:
        raise ContractError("endpoint target mismatch")
    task = exact(value["task"], {"kind", "promptRef", "inputRefs", "outputContractRef"})
    if task["kind"] != "llm-query":
        raise ContractError("unsupported task")
    c.ref("artifactRef", task["promptRef"])
    c.ref("schemaRef", task["outputContractRef"])
    for ref in unique_list(task["inputRefs"], "REQ-001", maximum=32):
        c.ref("artifactRef", ref)
    limits = exact(value["limits"], {"timeoutSeconds", "maxArtifacts", "maxOutputBytes"})
    bounded_int(limits["timeoutSeconds"], 1, 3600, "timeoutSeconds")
    bounded_int(limits["maxArtifacts"], 0, 64, "maxArtifacts")
    bounded_int(limits["maxOutputBytes"], 1, 16777216, "maxOutputBytes")
    auth = exact(value["authority"], {"mode", "intentRef", "grantRef", "planHash", "singleUse"})
    if auth["mode"] != "external-exact-grant" or auth["singleUse"] is not True:
        raise ContractError("invalid authority binding")
    c.ref("intentRef", auth["intentRef"])
    c.ref("grantRef", auth["grantRef"])
    c.ref("sha256", auth["planHash"])


def validate_receipt(c: Any, value: Any, schema_uri: str) -> None:
    reject_sensitive_keys(value)
    reject_secret_material(value)
    keys = {
        "$schema",
        "schema",
        "requestId",
        "runtimeRef",
        "planHash",
        "inputHash",
        "outcome",
        "startedAt",
        "completedAt",
        "artifactRefs",
        "evidenceRefs",
        "secretFree",
        "handleRedacted",
        "promptInline",
        "outputInline",
    }
    value = exact(value, keys, {"outputHash"})
    if (
        value["$schema"] != schema_uri
        or value["schema"] != "wellmanifest.account-runtime-receipt/v1"
    ):
        raise ContractError("unsupported receipt schema")
    c.ref("identifier", value["requestId"])
    c.ref("runtimeRef", value["runtimeRef"])
    for name in ("planHash", "inputHash"):
        c.ref("sha256", value[name])
    if "outputHash" in value:
        c.ref("sha256", value["outputHash"])
    outcome = str_choice(value["outcome"], RECEIPT_OUTCOMES, "unsupported receipt outcome")
    start = bounded_datetime(value["startedAt"])
    end = bounded_datetime(value["completedAt"])
    if end < start:
        raise ContractError("receipt time reversed")
    artifact_refs = unique_list(value["artifactRefs"], "RCPT-001", maximum=64)
    for ref in artifact_refs:
        c.ref("artifactRef", ref)
    evidence_refs = unique_list(value["evidenceRefs"], "RCPT-001", minimum=1, maximum=64)
    for ref in evidence_refs:
        c.ref("evidenceRef", ref)
    if outcome == "executed" and (not artifact_refs or "outputHash" not in value):
        raise ContractError("executed receipt lacks artifact proof")
    if (
        value["secretFree"] is not True
        or value["handleRedacted"] is not True
        or value["promptInline"] is not False
        or value["outputInline"] is not False
    ):
        raise ContractError("receipt contains unsafe inline data")


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        fval = float(value)
    except OverflowError:
        return None
    return fval if math.isfinite(fval) else None


def validate_observation_freshness(
    observed_at_str: str | None,
    reset_at_str: str | None = None,
    now_epoch: float | None = None,
    ttl_seconds: float = 86400.0,
    skew_tolerance_seconds: float = 60.0,
) -> tuple[str, bool]:
    """Validate observation timestamp freshness per INV-AR-004."""
    if not observed_at_str or not isinstance(observed_at_str, str):
        return ("unknown", False)
    ttl = _finite_number(ttl_seconds)
    skew = _finite_number(skew_tolerance_seconds)
    now = time.time() if now_epoch is None else _finite_number(now_epoch)
    if ttl is None or ttl < 0 or skew is None or skew < 0 or now is None:
        return ("unknown", False)
    try:
        obs_epoch = bounded_datetime(observed_at_str).timestamp()
    except ContractError:
        return ("unknown", False)
    if obs_epoch > now + skew:
        return ("future_invalid", False)
    if reset_at_str is not None:
        if not isinstance(reset_at_str, str) or not reset_at_str:
            return ("unknown", False)
        try:
            reset_epoch = bounded_datetime(reset_at_str).timestamp()
        except ContractError:
            return ("unknown", False)
        if now >= reset_epoch:
            return ("expired_reset", False)
    if now - obs_epoch > ttl:
        return ("stale", False)
    return ("fresh", True)


def verify_observation_freshness_suite() -> dict[str, Any]:
    now_ref = 1760000000.0
    t_fresh = datetime.fromtimestamp(now_ref - 3600, tz=UTC).isoformat()
    assert validate_observation_freshness(t_fresh, now_epoch=now_ref) == ("fresh", True)
    t_stale = datetime.fromtimestamp(now_ref - 90000, tz=UTC).isoformat()
    assert validate_observation_freshness(t_stale, now_epoch=now_ref) == ("stale", False)
    t_obs = datetime.fromtimestamp(now_ref - 1800, tz=UTC).isoformat()
    t_reset = datetime.fromtimestamp(now_ref - 60, tz=UTC).isoformat()
    assert validate_observation_freshness(t_obs, reset_at_str=t_reset, now_epoch=now_ref) == (
        "expired_reset",
        False,
    )
    t_future = datetime.fromtimestamp(now_ref + 3600, tz=UTC).isoformat()
    assert validate_observation_freshness(t_future, now_epoch=now_ref) == (
        "future_invalid",
        False,
    )
    assert validate_observation_freshness("2026-08-12T12:00:00", now_epoch=now_ref) == (
        "unknown",
        False,
    )
    assert validate_observation_freshness(None, now_epoch=now_ref) == ("unknown", False)
    return {
        "invariant": "INV-AR-004",
        "statesVerified": ["fresh", "stale", "expired_reset", "future_invalid", "unknown"],
        "ok": True,
    }
