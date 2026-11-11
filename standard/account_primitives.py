#!/usr/bin/env python3
"""Shared deterministic validation primitives for account-runtime and service-access v1."""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|token|secret|cookie|api[-_]?key|credential|private[-_]?key)",
    re.I,
)
SAFE_SECURITY_ASSERTIONS = {"secretFree"}
SECRET_MATERIAL = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{20,}|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}|\bsk-[A-Za-z0-9_-]{20,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"(?:password|passwd|token|secret|api[-_]?key)\s*[:=]\s*[^\s,;]{4,})",
    re.I,
)
RFC3339_DT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")


class ContractError(ValueError):
    """A bounded error that never repeats untrusted input."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ContractError("duplicate JSON key")
        obj[key] = value
    return obj


def strict_loads(raw: str) -> Any:
    return json.loads(raw, object_pairs_hook=_unique_pairs)


def load_strict_json(path: Path) -> Any:
    return strict_loads(path.read_text(encoding="utf-8"))


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("expected an object")
    optional_keys = optional or set()
    if set(value) - required - optional_keys:
        raise ContractError("undeclared field")
    if required - set(value):
        raise ContractError("missing required field")
    return value


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


def bounded_list(value: Any, code: str = "DOC-001", *, minimum: int = 0) -> list[Any]:
    if not isinstance(value, list) or len(value) < minimum:
        raise ContractError(f"{code}: expected a bounded list")
    return value


def unique_list(value: Any, code: str = "DOC-001", *, minimum: int = 0) -> list[Any]:
    items = bounded_list(value, code, minimum=minimum)
    try:
        unique = len(set(items)) == len(items)
    except TypeError as error:
        raise ContractError(f"{code}: list contains a non-scalar value") from error
    if not unique:
        raise ContractError(f"{code}: duplicate list member")
    return items


def assert_closed_schema(node: Any, error_message: str = "object schema is not closed") -> None:
    if isinstance(node, dict):
        if node.get("type") == "object" and node.get("additionalProperties") is not False:
            raise ContractError(error_message)
        for child in node.values():
            assert_closed_schema(child, error_message)
    elif isinstance(node, list):
        for child in node:
            assert_closed_schema(child, error_message)


def reject_sensitive_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE_KEY.search(key) and key not in SAFE_SECURITY_ASSERTIONS:
                raise ContractError("sensitive data channel")
            reject_sensitive_keys(child)
    elif isinstance(value, list):
        for child in value:
            reject_sensitive_keys(child)


def reject_secret_material(
    value: Any, error_message: str = "credential material is forbidden"
) -> None:
    if isinstance(value, dict):
        for child in value.values():
            reject_secret_material(child, error_message)
    elif isinstance(value, list):
        for child in value:
            reject_secret_material(child, error_message)
    elif isinstance(value, str) and SECRET_MATERIAL.search(value):
        raise ContractError(error_message)


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
    try:
        obs_epoch = bounded_datetime(observed_at_str).timestamp()
    except ContractError:
        return ("unknown", False)

    now = now_epoch if now_epoch is not None else time.time()
    if obs_epoch > now + skew_tolerance_seconds:
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

    if now - obs_epoch > ttl_seconds:
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
