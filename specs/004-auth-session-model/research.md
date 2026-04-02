# Research: Authentication and Session Model

## Authentication Flow Shape

- Decision: Use an explicit two-step challenge-response flow over the existing
  protocol: `BeginAuthentication` issues a bounded challenge, and
  `CompleteAuthentication` proves possession of the configured role credential.
- Rationale: The current transport is untrusted and reconnectable. A challenge-
  response flow makes session establishment explicit, replay-bounded, and
  reviewable instead of treating transport attachment as implicit authority.
- Alternatives considered: Implicit authenticated sessions based only on USB or
  developer-console presence were rejected because they collapse transport reach
  into privilege and weaken least-privilege review.

## Credential Storage Model

- Decision: Persist only bounded verifier records and policy metadata for each
  role, never plaintext reusable credentials.
- Rationale: The device needs durable authentication policy, but storing raw
  reusable secrets in flash would widen exposure if persistence is copied or
  inspected. Verifier-only records keep the design honest and narrow.
- Alternatives considered: Persisting plaintext passwords, PINs, or raw shared
  secrets was rejected because it is unnecessary and incompatible with the
  stated secret-lifecycle requirements.

## Session Cardinality

- Decision: Support one active authenticated privileged session in v1, plus the
  existing developer-mode session that is compile-time excluded from production.
- Rationale: The current engine already models a single current session state.
  One active session keeps authorization deterministic and bounded on RP2350
  while still covering administrative use.
- Alternatives considered: Multiple concurrent authenticated sessions were
  rejected for v1 because they add coordination, invalidation, and replay-state
  complexity without a demonstrated immediate need.

## Role Model

- Decision: Keep a fixed reviewed role set for v1: `bootstrap`,
  `administrator`, `recovery`, and `key_manager`, with `public` and
  `developer` remaining special non-production or unauthenticated states.
- Rationale: The current command surface already groups naturally into those
  authority classes. A fixed mapping is easier to review than a generic policy
  graph.
- Alternatives considered: Dynamic per-command permission graphs were rejected
  because they complicate persistence, testing, and auditability.

## Privileged Request Freshness

- Decision: Bind privileged requests to an active session identifier plus a
  monotonic per-session request counter tracked by a bounded replay window.
- Rationale: Replay resistance should not depend only on transport sequencing.
  A per-session counter gives deterministic freshness checks for privileged
  commands and clean invalidation on session reset.
- Alternatives considered: Timestamp-based freshness was rejected because the
  device has no trusted wall clock. Fingerprint-only replay detection was
  rejected because it does not provide an explicit freshness contract.

## Session Expiry and Invalidation

- Decision: Expire sessions on any of: explicit logout, reboot, developer reset,
  zeroize, lifecycle transition that changes authority assumptions, failure-
  counter lockout, or session-id mismatch.
- Rationale: Session authority must never silently survive the conditions that
  granted it. Tying invalidation to lifecycle changes prevents stale authority
  from leaking across provisioning or recovery boundaries.
- Alternatives considered: Letting sessions survive reboot or major lifecycle
  transitions was rejected because it creates ambiguous privilege carryover.

## Failed Attempt Handling

- Decision: Use bounded failure counters with progressive backoff and an
  explicit temporary lockout state for repeated authentication failures.
- Rationale: The platform cannot promise resistance to unlimited online
  guessing. A documented backoff and lockout policy is the honest and testable
  control.
- Alternatives considered: Unlimited retry was rejected because it makes the
  authentication surface cheap to brute-force. Permanent lockout on first
  threshold breach was rejected because it is operationally brittle for a v1
  lab-facing product.

## Boot Persistence Scope

- Decision: Persist credential policy, role verifiers, and failure-accounting
  baseline, but do not persist active authenticated sessions across reboot.
- Rationale: Credentials and policy are durable configuration; active sessions
  are transient authority and should die on reset. This matches least-privilege
  and simplifies safe recovery after reboot.
- Alternatives considered: Persisting authenticated session state was rejected
  because it weakens the boundary between device reset and authority reset.

## Verification Strategy

- Decision: Keep most authentication and authorization behavior testable in the
  shared `protocol` crate, then extend the host probe to cover challenge flow,
  expiry, replay denial, invalidation, and lockout behavior on hardware.
- Rationale: The risk is primarily in state-machine and parser correctness, not
  in HAL-specific behavior. Host tests provide deeper negative-path coverage.
- Alternatives considered: Hardware-only validation was rejected because it is
  slower, less reproducible, and weaker for edge-case abuse scenarios.
