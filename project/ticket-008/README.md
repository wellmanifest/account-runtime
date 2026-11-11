# Ticket 008: Harden account-runtime float overflow, huge-int freshness, URI control chars, and service-access maxItems parity

- **ID**: ticket-008
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, modularizing Python modules under 500 lines, and hardening conformance across `wellmanifest/*` standard repositories.

Close the advisory findings on `standard/account_primitives.py` (`parse_float` finite check for `1e999` float overflow in `strict_loads`, `OverflowError` catch on huge integers like `10**400` in `_finite_number` / `canonical`, whitespace/control-character rejection in `validate_safe_uri_segments`, and `"if"`/`"not"`/`"contains"` predicate tolerance in `assert_closed_schema`), enforce full `maxItems` schema parity across `standard/service_access_conformance.py`, add regression tests in `standard/test_account_runtime_hardening.py`, and mark merged `ticket-007` `DONE`.

## Acceptance criteria

- [x] AC-01: Reject `1e999`/`-1e999` float overflow in `strict_loads`, handle `OverflowError` fail-closed in `_finite_number` and `canonical`, reject whitespace/control characters in `validate_safe_uri_segments`, and tolerate conditional JSON Schema predicates in `assert_closed_schema`.
- [x] AC-02: Enforce every `maxItems` bound declared in `standard/service-access.schema.json` across `standard/service_access_conformance.py` while keeping all Python modules strictly `< 500` lines.
- [x] AC-03: Add regression tests in `standard/test_account_runtime_hardening.py`, mark merged `ticket-007` `DONE`, and pass `ruff`, `conformance.py --all`, `pytest`, `wellman check`, and governance checks.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
