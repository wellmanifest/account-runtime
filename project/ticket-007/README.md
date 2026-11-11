# Ticket 007: Harden account-runtime JSON/file bounds, observation freshness, and schema parity

- **ID**: ticket-007
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Enforce `O_NOFOLLOW | O_NONBLOCK` regular-file verification and 4 MiB input
bounds across JSON and grammar loading, reject `NaN`/`Infinity` and deep JSON
(`MAX_JSON_DEPTH = 64`) iteratively without `RecursionError`, make
`validate_observation_freshness` fail closed on `NaN`/`Inf`/`bool`/negative
bounds, close schema-parity gaps (`services.classification`, `evidence.kind`,
`evidence.sourceRef`, `links.relation`/`confidence`, `persistence.hostExposure`,
`clipboard`, `profileVolumeRef`, `state.*`, `control.operations`,
`humanVisible`, `kvmConnectorRef`, `receipt.outcome`, URI `..`/`//` traversal,
and `endpointRef` slug prefix-collision), keep all Python files strictly below
500 lines, and close merged `ticket-006`.

## Acceptance criteria

- [x] AC-01: Harden `account_primitives.py`, `conformance.py`, and
      `service_access_conformance.py` for regular-file bounds, finite/depth-bounded
      JSON, fail-closed freshness, and full schema parity, with regression tests
      in `standard/test_account_runtime_hardening.py`.
- [x] AC-02: Keep every Python module strictly below 500 lines and pass
      `ruff check standard tests`.
- [x] AC-03: Mark merged `project/ticket-006/README.md` `DONE` / `PUBLICATION`
      and pass `pytest -q`, `./project/governance-check.sh --base origin/main`,
      and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
