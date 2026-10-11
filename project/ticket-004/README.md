# Ticket 004: define INV-AR-004 observation freshness and budget metric degradation standard

- **ID**: ticket-004
- **Owner**: agent:antigravity
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-10-11

## Goal and scope

Standardize the normative invariant `INV-AR-004` (Observation Freshness & Metric Degradation) within `wellmanifest/account-runtime`. Require explicit ISO 8601 UTC observation timestamps, define state transitions (`fresh`, `stale`, `expired_reset`, `future_invalid`, `unknown`), mandate degradation of effective quota/balance to `UNKNOWN` when not fresh, and isolate historical metric values from active dispatch authority.

## Acceptance criteria

- [x] AC-01: Document normative invariant `INV-AR-004: Observation Freshness & Metric Degradation` in `docs/ARCHITECTURE.md` and publish specification in `docs/OBSERVATION_FRESHNESS.md`.
- [x] AC-02: Implement deterministic `validate_observation_freshness` and adversarial test suites in `standard/conformance.py`.
- [x] AC-03: All adversarial cases (stale, expired reset, future invalid, missing timestamp) pass in `conformance.py --all`.
- [x] AC-04: `./project/governance-check.sh` passes with 0 errors and 0 warnings (`GOV-PASS`).

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
