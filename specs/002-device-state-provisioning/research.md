# Research: Device State and Provisioning

## Lifecycle State Representation

- Decision: Model the device lifecycle as a single persisted finite-state
  machine with explicit transition intents and fail-safe terminal outcomes.
- Rationale: A single authoritative lifecycle record is easier to review,
  easier to validate after reboot, and avoids privilege drift between separate
  "provisioning status" and "operational status" flags.
- Alternatives considered: Separate booleans for provisioned/locked/recovery
  were rejected because they create invalid combinations and make reboot
  recovery ambiguous.

## Persistent Transition Journal

- Decision: Persist lifecycle changes through a compact provisioning record that
  includes current state, pending transition intent, monotonic revision, owner
  binding metadata, and integrity protection.
- Rationale: Interrupted provisioning, lock, transfer, recovery, and zeroize
  operations must recover predictably after reboot. Recording both committed
  state and in-flight intent allows the firmware to fail closed instead of
  guessing which step finished.
- Alternatives considered: Best-effort direct overwrite of the current state
  was rejected because power loss could leave a partially updated record with
  no safe way to distinguish success from corruption.

## Ownership Bootstrap Model

- Decision: Use a two-phase ownership bootstrap: claim intent followed by final
  activation of an owner-bound provisioning record.
- Rationale: Separating intent from activation gives the device a safe place to
  reject malformed payloads, repeated requests, or interrupted writes without
  granting operational access prematurely.
- Alternatives considered: One-shot provisioning was rejected because any write
  interruption would blur the line between "factory" and "owned" and force
  recovery semantics into the initial bootstrap.

## State-Gated Command Enforcement

- Decision: Keep command authorization state-driven in the shared protocol
  crate, with each lifecycle command declaring allowed source states, required
  authority, idempotency, and resulting target state.
- Rationale: This keeps enforcement reviewable and testable on the host, not
  buried in HAL-specific firmware paths.
- Alternatives considered: Dispatch-time ad hoc checks in `firmware/src/main.rs`
  were rejected because they scatter security policy and make contract tests
  weaker.

## Recovery Workflow

- Decision: Recovery is a distinct restricted state entered only by explicit
  administrator action or by detection of interrupted privileged transitions;
  it does not automatically restore operational access.
- Rationale: Recovery should preserve control and auditability, not serve as an
  informal bypass around lock or ownership checks.
- Alternatives considered: Auto-resume into operational mode after restart was
  rejected because it could mask interrupted destructive or administrative
  flows.

## Post-Zeroize Behavior

- Decision: Zeroize ends in a defined non-operational state that requires fresh
  provisioning before any owned operations become available.
- Rationale: A destructive lifecycle event must not leave stale ownership or
  authorization context in memory or flash.
- Alternatives considered: Returning directly to fully operational or vaguely
  "factory-like" behavior without an explicit record was rejected because it
  would make post-destruction trust ambiguous.

## Host and Test Strategy

- Decision: Extend host-side protocol tests for state transitions and add probe
  coverage for public lifecycle reporting, while treating flash-failure and
  interrupted-transition scenarios as deterministic simulated tests in the
  shared protocol crate.
- Rationale: Most lifecycle logic can and should be validated off-device before
  firmware integration, while hardware verification focuses on public behavior.
- Alternatives considered: Hardware-only validation was rejected because it is
  slower, harder to reproduce, and weaker at exhaustively checking denied
  transitions and corruption cases.
