#!/usr/bin/env python3
"""Shared deterministic validation primitives for account-runtime and service-access v1."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64

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
RFC3339_DT = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+\.[^@\s]+$")


class ContractError(ValueError):
    """A bounded error that never repeats untrusted input."""


def read_regular_utf8(path: Path, max_bytes: int = MAX_INPUT_BYTES) -> str:
    if path.is_symlink():
        raise ContractError("symlinked input path is forbidden")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ContractError("unable to open input file") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ContractError("input path must be a regular file")
        if info.st_size > max_bytes:
            raise ContractError("input file exceeds maximum size")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, 65536):
            total += len(chunk)
            if total > max_bytes:
                raise ContractError("input file exceeds maximum size")
            chunks.append(chunk)
    except OSError as error:
        raise ContractError("unable to read input file") from error
    finally:
        os.close(fd)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContractError("input file is not valid UTF-8") from error


def _check_json_depth(value: Any, max_depth: int = MAX_JSON_DEPTH) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            if depth >= max_depth:
                raise ContractError("JSON nesting exceeds maximum depth")
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ContractError("JSON object key must be a string")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            if depth >= max_depth:
                raise ContractError("JSON nesting exceeds maximum depth")
            for child in current:
                stack.append((child, depth + 1))


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str):
            raise ContractError("JSON object key must be a string")
        if key in obj:
            raise ContractError("duplicate JSON key")
        obj[key] = value
    return obj


def _reject_constant(_token: str) -> Any:
    raise ContractError("non-finite JSON constant is forbidden")


def _parse_finite_float(token: str) -> float:
    parsed = float(token)
    if not math.isfinite(parsed):
        raise ContractError("non-finite JSON number is forbidden")
    return parsed


def strict_loads(raw: str) -> Any:
    if (
        not isinstance(raw, str)
        or len(raw.encode("utf-8", errors="surrogatepass")) > MAX_INPUT_BYTES
    ):
        raise ContractError("JSON input exceeds maximum size")
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise ContractError("invalid JSON document") from error
    _check_json_depth(parsed)
    return parsed


def load_strict_json(path: Path) -> Any:
    return strict_loads(read_regular_utf8(path))


def canonical(value: Any) -> str:
    _check_json_depth(value)
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError, RecursionError, OverflowError) as error:
        raise ContractError("value is not canonicalizable JSON") from error


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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
    if any(ch.isspace() or ord(ch) < 32 for ch in uri):
        raise ContractError(message)
    if "://" in uri:
        rest = uri.partition("://")[2]
        if "//" in rest or any(seg in {".", ".."} for seg in rest.split("/")[1:]):
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
    map_keys = {"properties", "$defs", "dependentSchemas"}
    predicate_keys = {"if", "not", "contains"}
    stack: list[tuple[Any, int, bool]] = [(node, 0, False)]
    while stack:
        current, depth, is_map = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ContractError("schema nesting exceeds maximum depth")
        if isinstance(current, dict):
            if (
                not is_map
                and current.get("type") == "object"
                and current.get("additionalProperties") is not False
            ):
                raise ContractError(error_message)
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ContractError("schema object key must be a string")
                if not is_map and key in predicate_keys:
                    continue
                stack.append((child, depth + 1, not is_map and key in map_keys))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1, False))


def reject_sensitive_keys(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ContractError("JSON nesting exceeds maximum depth")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ContractError("JSON object key must be a string")
                if SENSITIVE_KEY.search(key) and key not in SAFE_SECURITY_ASSERTIONS:
                    raise ContractError("sensitive data channel")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))


def reject_secret_material(
    value: Any, error_message: str = "credential material is forbidden"
) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ContractError("JSON nesting exceeds maximum depth")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ContractError("JSON object key must be a string")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, str) and SECRET_MATERIAL.search(current):
            raise ContractError(error_message)


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
