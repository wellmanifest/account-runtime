# Ticket 011: Modularize account_io and harden relative symlink traversal, JSON digit bounds, and service name controls

- **ID**: ticket-011
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Extract bounded regular-file UTF-8 I/O, finite JSON parsing, canonicalization,
digest, and secret/sensitive-key scanning into `standard/account_io.py`, and
move `validate_receipt` into `standard/account_primitives.py` (with full
`__all__` re-exports in `standard/account_primitives.py` and
`standard/conformance.py`) so every module under `standard/` stays well below
500 lines. Harden `_reject_ancestor_symlinks` against relative `link_dir/..`,
`../link_dir`, and un-normalized absolute symlink-parent traversal, bound JSON
integer digit count (`<= 309`) before `int()` conversion in `strict_loads`,
reject ASCII C0/DEL control characters in `validate_graph` service `name`,
enforce `allow_nan=False` in CLI JSON output, expand
`standard/test_account_runtime_hardening.py`, and reconcile merged
`project/ticket-010/README.md` to `DONE`.

## Acceptance criteria

- [x] AC-01: Extract `standard/account_io.py` and keep all `standard/*.py`
      modules strictly `< 500` lines while preserving public re-exports.
- [x] AC-02: Reject relative `link_dir/..`, `../link_dir`, and un-normalized
      absolute symlink-parent traversal, bound JSON integer digits before
      `int()` conversion in `strict_loads`, and reject ASCII C0/DEL control
      characters in `validate_graph` service `name`, passing `ruff`,
      `python3 standard/conformance.py --all`, and `pytest`.
- [x] AC-03: Reconcile merged `project/ticket-010/README.md` to `DONE` and pass
      `./project/governance-check.sh --base origin/main` and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
