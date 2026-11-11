# Ticket 010: Harden account-runtime 4300-digit JSON ints, absolute symlink ancestors, key secret scanning, and digest UTF-8

- **ID**: ticket-010
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, and hardening across `wellmanifest/*` standard repositories.

Catch 4300+ digit integer `ValueError` in `strict_loads`, extend symlink-ancestor rejection in `read_regular_utf8` to absolute paths, validate strict UTF-8 string input in `digest`, scan JSON object keys and enforce UTF-8 strings in `reject_secret_material` and `reject_sensitive_keys` in `standard/account_primitives.py` (strictly `< 500` lines), expand `standard/test_account_runtime_hardening.py`, and reconcile merged `project/ticket-009/README.md` to `DONE`.

## Acceptance criteria

- [x] AC-01: `strict_loads`, `digest`, `reject_secret_material`, `reject_sensitive_keys`, and `read_regular_utf8` deterministically raise `ContractError` on 4300+ digit JSON integers, lone UTF-16 surrogates, secret-bearing JSON keys, and absolute-path symlink ancestors.
- [x] AC-02: Every Python module stays strictly `< 500` lines and passes `ruff check --no-cache standard tests`.
- [x] AC-03: Regression tests pass alongside `python3 standard/conformance.py --all`, `./project/governance-check.sh --base origin/main`, and `wellman check`, and merged `project/ticket-009/README.md` is marked `DONE`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
