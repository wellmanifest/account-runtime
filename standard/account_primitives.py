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
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z"
)
EMAIL_RE = re.compile(
    r"\A(?!.*\.\.)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z"
)


class ContractError(ValueError):
    """A bounded error that never repeats untrusted input."""


def compile_anchored_pattern(raw: str) -> re.Pattern[str]:
    if not isinstance(raw, str) or not raw:
        raise ContractError("invalid regex pattern")
    body = raw[1:] if raw.startswith("^") else raw
    if body.endswith("$") and not body.endswith(r"\$"):
        body = body[:-1]
    return re.compile(rf"\A(?:{body})\Z")


def _reject_ancestor_symlinks(path: Path) -> None:
    if path.is_absolute():
        for anc in path.parents:
            if len(anc.parts) <= 2:
                break
            try:
                st = os.lstat(anc)
            except OSError as error:
                raise ContractError("unable to open input path ancestor") from error
            if stat.S_ISLNK(st.st_mode):
                raise ContractError("symlinked input ancestor is forbidden")
        return
    cur = Path()
    for part in path.parts[:-1]:
        if part in ("", "."):
            continue
        cur = cur / part
        try:
            st = os.lstat(cur)
        except OSError as error:
            raise ContractError("unable to open input path ancestor") from error
        if stat.S_ISLNK(st.st_mode):
            raise ContractError("symlinked input ancestor is forbidden")


def read_regular_utf8(path: Path, max_bytes: int = MAX_INPUT_BYTES) -> str:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ContractError("invalid maximum byte size")
    if not isinstance(path, (Path, str)):
        raise ContractError("invalid input path")
    candidate = path if isinstance(path, Path) else Path(path)
    _reject_ancestor_symlinks(candidate)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        lst = os.lstat(candidate)
        if not stat.S_ISREG(lst.st_mode):
            raise ContractError("symlinked or non-regular input path is forbidden")
        fd = os.open(candidate, flags)
    except OSError as error:
        raise ContractError("unable to open input file") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ContractError("input path must be a regular file")
        if (lst.st_dev, lst.st_ino) != (info.st_dev, info.st_ino):
            raise ContractError("input file identity changed during open")
        if info.st_size > max_bytes:
            raise ContractError("input file exceeds maximum size")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, min(65536, max_bytes + 1 - total)):
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


def _check_finite_number(value: int | float) -> None:
    try:
        finite = math.isfinite(float(value))
    except OverflowError as error:
        raise ContractError("non-finite JSON number is forbidden") from error
    if not finite:
        raise ContractError("non-finite JSON number is forbidden")


def _check_utf8_str(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ContractError("lone UTF-16 surrogate is forbidden") from error


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
                _check_utf8_str(key)
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            if depth >= max_depth:
                raise ContractError("JSON nesting exceeds maximum depth")
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, str):
            _check_utf8_str(current)
        elif isinstance(current, (int, float)) and not isinstance(current, bool):
            _check_finite_number(current)


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
    if not isinstance(raw, str):
        raise ContractError("JSON input must be a string")
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ContractError("invalid UTF-8 JSON input") from error
    if len(encoded) > MAX_INPUT_BYTES:
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
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ContractError("invalid JSON document") from error
    _check_json_depth(parsed)
    return parsed


def load_strict_json(path: Path, max_bytes: int = MAX_INPUT_BYTES) -> Any:
    return strict_loads(read_regular_utf8(path, max_bytes=max_bytes))


def canonical(value: Any) -> str:
    _check_json_depth(value)
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError, RecursionError, OverflowError) as error:
        raise ContractError("value is not canonicalizable JSON") from error


def digest(value: str) -> str:
    if not isinstance(value, str):
        raise ContractError("digest input must be a string")
    _check_utf8_str(value)
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
        if port_sep and (
            ":" in port or not port.isdigit() or not 1 <= int(port) <= 65535
        ):
            raise ContractError(message)
        if slash and (
            not path or any(seg in {"", ".", ".."} for seg in re.split(r"[/:]", path))
        ):
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
                _check_utf8_str(key)
                if SENSITIVE_KEY.search(key) and key not in SAFE_SECURITY_ASSERTIONS:
                    raise ContractError("sensitive data channel")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, str):
            _check_utf8_str(current)


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
                _check_utf8_str(key)
                if SECRET_MATERIAL.search(key):
                    raise ContractError(error_message)
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, str):
            _check_utf8_str(current)
            if SECRET_MATERIAL.search(current):
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
