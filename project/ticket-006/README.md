# Ticket 006: Add standalone pytest and unittest suite for account-runtime conformance

- **ID**: ticket-006
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Add a standalone `pytest` and `unittest` test suite under
`tests/test_account_runtime.py` covering `account-runtime` and `service-access`
conformance validators, `oneOf` list-schema closure, duplicate JSON key
rejection, `bool`/`str` request limit rejection, inline secret material
scanning, timezone-less timestamp freshness handling, and `--file` CLI exit
codes, and mark merged `ticket-005` as `DONE`.

## Acceptance criteria

- [x] AC-01: Add `tests/test_account_runtime.py` exercising positive documents,
      adversarial regressions, observation freshness edge cases, and `--file`
      CLI exit codes under both `pytest` and `unittest`.
- [x] AC-02: Reconcile merged `project/ticket-005/README.md` to `DONE` /
      `PUBLICATION`.
- [x] AC-03: Pass `ruff check standard tests`, `pytest -q`,
      `./project/governance-check.sh --base origin/main`, and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
