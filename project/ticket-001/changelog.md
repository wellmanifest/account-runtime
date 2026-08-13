# Ticket Changelog (ticket-001)

## [0.1.0] - 2026-08-12

- Initial governance scaffold created.
- No human participant identity or content was generated.
- Recorded the five-file standard boundary, Docker conformance requirement and
  session execution authorization.
- Added account graph, runtime binding, invocation and receipt contracts.
- Added constrained invocation generation and 15 adversarial fail-closed cases.
- Documented readiness, restart/session persistence, noVNC/KVM and artifact flow.
- Recorded explicit authority to create the public remote, commit the bounded
  diff, push the ticket branch and open a pull request without treating that
  request as trusted merge approval.

## 2026-08-13 Validator secret-scan follow-up

- Replaced the origin-query adversarial fixture `token=x` with the inert
  assignment `token=redacted` so the case still rejects query-bearing origins
  without looking like embedded credential material.
