#!/usr/bin/env python3
"""Bounded regular-file UTF-8 I/O, finite JSON parsing, and secret scanning for account-runtime."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_INT_DIGITS = 309

SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|token|secret|cookie|api[-_]?key|credential|private[-_]?key)",
    re.I,
)
SAFE_SECURITY_ASSERTIONS = {"secretFree"}
SECRET_MATERIAL = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRI"
    r"VATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{20,}|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}|\bsk-[A-Za-z0-9_-]{20,}|"
    r"\bAK"
    r"IA[0-9A-Z]{16}\b|"
    r"(?:password|passwd|token|secret|api[-_]?key)\s*[:=]\s*[^\s,;]{4,})",
    re.I,
)


class ContractError(ValueError):
    """A bounded error that never repeats untrusted input."""


def _reject_ancestor_symlinks(path: Path) -> None:
    raw_start = 3 if path.is_absolute() else 1
    for idx in range(raw_start, len(path.parts)):
        if path.parts[idx - 1] in ("", ".", ".."):
            continue
        prefix = Path(*path.parts[:idx])
        try:
            st = os.lstat(prefix)
        except OSError as error:
            raise ContractError("unable to open input path ancestor") from error
        if stat.S_ISLNK(st.st_mode):
            raise ContractError("symlinked input ancestor is forbidden")
    abs_path = Path(os.path.abspath(os.fspath(path)))
    for anc in abs_path.parents:
        if len(anc.parts) <= 2:
            break
        try:
            st = os.lstat(anc)
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
    if type(max_depth) is not int or max_depth < 1:
        raise ContractError("invalid JSON nesting depth bound")
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


def _parse_finite_int(token: str) -> int:
    digits = token[1:] if token.startswith(("+", "-")) else token
    if len(digits) > MAX_JSON_INT_DIGITS:
        raise ContractError("non-finite JSON number is forbidden")
    parsed = int(token)
    _check_finite_number(parsed)
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
            parse_int=_parse_finite_int,
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
