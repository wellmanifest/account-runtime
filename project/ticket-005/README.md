# Ticket 005: Modularize under 500 lines and harden account-runtime and service-access conformance

- **ID**: ticket-005
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

Modularize `wellmanifest/account-runtime` conformance validators so every Python
file stays strictly under 500 lines (`standard/conformance.py` 478 lines,
`standard/service_access_conformance.py` 466 lines, `standard/account_fixtures.py`
295 lines, `standard/account_primitives.py` 205 lines), fix schema-closure,
boolean-for-integer, duplicate-key, naive-timestamp, and secret-scanning defects,
add `--file` validation CLI and `pyproject.toml`, and close merged `ticket-003`
and `ticket-004`.

## Acceptance criteria

- [x] AC-01: Split `standard/conformance.py` (down from 804 lines) into
      `< 500`-line modules with shared primitives in `standard/account_primitives.py`.
- [x] AC-02: Fix `assert_closed_schema` recursion across list subschemas (`oneOf`),
      reject `bool` and non-`int` values in `validate_request` `limits`, reject
      duplicate JSON keys via `strict_loads`, enforce strict RFC3339 `T` + timezone
      in `bounded_datetime` and `validate_observation_freshness`, scan inline
      secret material across all `account-runtime` documents, and expose `--file`
      CLI validation.
- [x] AC-03: Add `pyproject.toml`, close `ticket-003` and `ticket-004`, and pass
      `ruff check standard`, `python3 standard/conformance.py --all`, networkless
      Docker container execution, `./project/governance-check.sh --base origin/main`,
      and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
