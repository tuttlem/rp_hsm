# Research: Policy Enforcement

## Decision: Use a static policy matrix with explicit bounded approval records

### Rationale

- The current firmware already has explicit command IDs, role checks, lifecycle
  states, key metadata, and session freshness rules. A static matrix builds on
  that reviewable structure instead of introducing a dynamic interpreter.
- Static compiled rules fit the RP2350 constraints: deterministic execution,
  bounded memory, and no runtime rule parsing.
- A bounded approval record per protected action class is enough for v1
  dual-control semantics without inventing a general-purpose workflow engine.

### Alternatives considered

- Dynamic policy language or bytecode engine: rejected because it would expand
  the attack surface and reduce reviewability on a constrained device.
- Host-maintained policy decisions: rejected because the feature explicitly
  requires device-local enforcement at the HSM boundary.

## Decision: Evaluate policy inputs in a fixed order

### Rationale

- The policy decision will evaluate in this order:
  1. command definition and build visibility
  2. device lifecycle/state eligibility
  3. session role and freshness
  4. key metadata and key-usage constraints, if a managed key is touched
  5. approval requirements for protected actions
- A fixed order makes behavior deterministic, auditable, and easier to test.
- Conflicting rules fail closed because any unmet condition denies the request.

### Alternatives considered

- Priority-scored or overlapping rule selection: rejected because it obscures
  why a command was allowed and complicates review.
- Per-command bespoke logic: rejected because the repo has already reached the
  point where scattered conditionals are a security maintenance risk.

## Decision: Limit v1 dual-control to destructive actions with irreversible or high-impact outcomes

### Rationale

- The current command surface suggests the highest-risk operations are:
  - `ExecuteZeroize`
  - `DestroyPersistentKey`
  - `RecoverToProvisioned` / `ReactivateRecoveredProvisioning` when they change
    ownership-relevant lifecycle state
- Applying optional dual-control to all privileged commands would make normal
  administration cumbersome and would obscure the real risk boundary.
- A smaller protected-action set is compatible with the project constitution’s
  “minimal attack surface by default” requirement.

### Alternatives considered

- Dual-control for all lifecycle and key-management commands: rejected because
  it would add operational complexity without proportionate security value.
- No dual-control in v1: rejected because the spec explicitly calls for support
  for optional multi-party approval on the most sensitive actions.

## Decision: Represent approval state as a bounded, invalidatable ticket

### Rationale

- A ticket-style approval record can capture:
  - protected action class
  - initiating role
  - confirming role
  - target binding (e.g. key ID or device-wide action)
  - revision binding
  - expiry and invalidation conditions
- Tickets can be invalidated on lifecycle change, session invalidation, policy
  revision change, reboot ambiguity, or completion.
- This is easier to persist and reason about than a long-lived approval queue.

### Alternatives considered

- Multi-step approval queues with arbitrary participants: rejected because they
  exceed the bounded scope needed for the current command set.
- One-shot in-memory approvals only: rejected because destructive actions may
  span resets or deliberate revalidation boundaries in lab and recovery flows.

## Decision: Keep denial semantics bounded and non-oracular

### Rationale

- The device should distinguish operator-meaningful failure classes such as:
  - command unavailable
  - authorization denied
  - state denied
  - approval missing or stale
- It should not reveal hidden privilege structure, internal rule order, or
  secret key-state detail beyond what is necessary for safe behavior.
- The existing status-code model already provides a good base for bounded
  denial responses.

### Alternatives considered

- Fully opaque denials for every failure: rejected because it would make
  troubleshooting and review harder without meaningfully improving security.
- Highly specific rule-by-rule denial strings: rejected because they would
  create a privilege oracle for hostile hosts.

## Decision: Persist only policy profile and approval artifacts, not host-side policy logic

### Rationale

- Policy belongs at the firmware boundary, not in `rphsmtool` or host scripts.
- Persisting only the device-local profile and approval artifacts preserves the
  current architecture: `protocol` decides, `firmware` stores, host tooling
  observes and exercises the behavior.
- This avoids drift between a host-side “desired policy” and actual device
  enforcement.

### Alternatives considered

- Mirroring the policy engine in the CLI: rejected because it would create a
  second authority source and encourage host-side assumptions.
- No persisted approval/profile state: rejected because policy changes and
  reboot behavior must remain deterministic and reviewable.
