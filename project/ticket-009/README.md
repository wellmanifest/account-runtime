# Ticket 009: Harden account-runtime regular-file inode checks, integer overflow, URI host/colon segments, and regex anchors

- **ID**: ticket-009
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Enforce `os.lstat` + `os.fstat` `(st_dev, st_ino)` regular-file identity,
relative ancestor symlink rejection, and `max_bytes` integer/boolean bounds in
`standard/account_primitives.py:read_regular_utf8`; reject `10**400` integer
overflow and lone UTF-16 surrogates in `strict_loads`; harden
`validate_safe_uri_segments` against host `..`, out-of-range origin ports,
`\`, `?`, `#`, DEL (`0x7f`), and colon-delimited `..` or empty segments; detect
open implicit object schemas in `assert_closed_schema`; anchor all regexes with
`\A...\Z` across `account_primitives.py`, `conformance.py`, and
`service_access_conformance.py` (all strictly `< 500` lines); expand
`standard/test_account_runtime_hardening.py`; and mark merged
`project/ticket-008/README.md` `DONE` / `PUBLICATION`.

## Acceptance criteria

- [x] AC-01: Enforce `lstat`+`fstat` inode identity, relative ancestor symlink
      rejection, `strict_loads` huge-integer/surrogate rejection, URI
      host/port/colon/delimiter guards, implicit-object closed-schema checks,
      and `\A...\Z` regex anchors, passing `pytest -q` and
      `python3 standard/conformance.py --all`.
- [x] AC-02: Keep every Python module strictly below 500 lines and pass
      `ruff check standard tests`.
- [x] AC-03: Mark merged `project/ticket-008/README.md` `DONE` / `PUBLICATION`
      and pass `./project/governance-check.sh --base origin/main` and
      `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
