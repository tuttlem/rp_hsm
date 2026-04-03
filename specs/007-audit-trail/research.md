# Research: Audit Trail

## Decision 1: Use a fixed-capacity append-only audit journal in reserved flash

- **Decision**: Store audit events in a bounded append-only journal with a
  fixed event header, bounded detail payload, and retention-by-overwrite when
  capacity is reached.
- **Rationale**: The firmware already uses reserved flash persistence and
  bounded record designs. Audit storage needs deterministic capacity and clear
  overflow semantics, not unbounded growth or host-dependent logging.
- **Alternatives considered**:
  - In-memory only audit history: rejected because events would be lost on
    reboot and would not support incident review.
  - Host-streamed audit only: rejected because transport availability cannot be
    trusted during failures and would weaken the trust boundary.
  - Immutable/tamper-proof claims: rejected because the platform and current
    feature scope do not support them honestly.

## Decision 2: Add a dedicated audit retrieval command with paged results

- **Decision**: Expose an authorized retrieval path that returns bounded pages
  of events using explicit cursors or monotonic sequence bounds.
- **Rationale**: Audit review needs a real protocol surface, but responses must
  stay within the framing limits and must not dump unbounded history.
- **Alternatives considered**:
  - Reuse generic status output for logs: rejected because it would blur health
    reporting and audit review into one oversized interface.
  - Stream-all retrieval: rejected because it conflicts with bounded memory and
    deterministic response size requirements.

## Decision 3: Separate audit review from non-secret health reporting

- **Decision**: Keep audit retrieval privileged while exposing a separate
  redacted health-status command for safe operational visibility.
- **Rationale**: Audit entries require controlled disclosure, while operators
  still need non-secret health information without using debug firmware.
- **Alternatives considered**:
  - One combined observability endpoint: rejected because it risks either
    overexposing sensitive audit detail or underdelivering health information.
  - Developer-only health visibility: rejected because the feature explicitly
    requires approved operational observability in non-debug builds.

## Decision 4: Define an explicit audit event taxonomy

- **Decision**: Partition events into administrative actions, security denials,
  lifecycle transitions, persistence anomalies, and observability access.
- **Rationale**: Reviewability depends on stable event classes rather than free
  text messages or scattered ad hoc codes.
- **Alternatives considered**:
  - Arbitrary numeric-only event IDs with no class model: rejected because it
    makes review and retention policy harder to reason about.
  - Full traffic capture: rejected because the feature scope prioritizes
    security-relevant events, not exhaustive request logging.

## Decision 5: Redact by construction rather than post-processing

- **Decision**: Event payloads and health views will only encode reviewed
  non-secret fields, with no secret-bearing fields recorded and no attempt to
  sanitize raw command payloads after capture.
- **Rationale**: Preventing secret capture is safer and simpler than logging
  first and trying to redact later on constrained firmware.
- **Alternatives considered**:
  - Log raw payloads then filter: rejected because it risks transient or
    persisted secret leakage.
  - Role-dependent event body rewriting: rejected because it complicates
    determinism and reviewability.

## Decision 6: Fail safe on audit ambiguity and persistence corruption

- **Decision**: If audit storage decode fails or ordering is ambiguous, expose
  a bounded degraded state through health status and deny trusted retrieval until
  the store is reconciled or reset according to policy.
- **Rationale**: An HSM audit feature should not invent or guess history after
  corrupt persistence state.
- **Alternatives considered**:
  - Best-effort partial replay: rejected because it risks misleading security
    review.
  - Silent reset of audit history: rejected because it hides important failure
    conditions.
