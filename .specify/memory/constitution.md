<!--
Sync Impact Report
- Version change: template -> 1.0.0
- Modified principles:
  - Principle 1 -> I. Fail-Safe Security Boundaries
  - Principle 2 -> II. Explicit Secret Lifecycle Control
  - Principle 3 -> III. Deterministic and Verifiable Firmware
  - Principle 4 -> IV. Minimal Attack Surface by Default
  - Principle 5 -> V. Auditability and Reviewable Design
- Added sections:
  - Security Requirements
  - Development Workflow & Quality Gates
- Removed sections:
  - None
- Templates requiring updates:
  - ✅ updated .specify/templates/plan-template.md
  - ✅ updated .specify/templates/spec-template.md
  - ✅ updated .specify/templates/tasks-template.md
- Follow-up TODOs:
  - None
-->
# RP2350 HSM Constitution

## Core Principles

### I. Fail-Safe Security Boundaries
Every security-relevant code path MUST fail closed. Boot, provisioning, command
dispatch, authorization, key use, flash persistence, and upgrade logic MUST
reject invalid state explicitly and MUST NOT continue in a degraded or guessed
state. Recovery behavior MUST be designed up front and MUST preserve secrecy and
integrity over availability. Rationale: an HSM that keeps operating after an
invalid security transition is less trustworthy than one that halts safely.

### II. Explicit Secret Lifecycle Control
Secret material MUST have an explicit owner, lifetime, and destruction point.
Keys, seeds, plaintext credentials, derived secrets, and authorization tokens
MUST stay out of logs, debug interfaces, formatting traits, crash messages, and
general-purpose buffers. Secret-bearing memory MUST be bounded, minimized, and
zeroized when no longer needed. Rationale: uncontrolled copies are the fastest
way for constrained firmware to lose meaningful security properties.

### III. Deterministic and Verifiable Firmware
Firmware behavior and build outputs MUST be reproducible and reviewable.
Security-critical code MUST prefer deterministic state machines, bounded memory,
constant-time primitives where applicable, and explicit error handling over
implicit convenience patterns. Release artifacts MUST be built with hardened
settings and verified before deployment. Rationale: if behavior cannot be
predicted and reproduced, it cannot be audited with confidence.

### IV. Minimal Attack Surface by Default
Only the smallest set of transports, commands, privileges, and dependencies
needed for the current feature scope may be enabled by default. Debug or factory
capabilities MUST be isolated behind explicit build-time or provisioning gates
and MUST be removable from production images. New interfaces MUST arrive with
input bounds, malformed-input handling, abuse cases, and privilege checks before
implementation is considered complete. Rationale: every optional interface
becomes mandatory review and defense work.

### V. Auditability and Reviewable Design
Security properties MUST be obvious from the code, the specification, and the
task plan. Security-sensitive state transitions MUST be represented explicitly.
Non-trivial invariants, threat assumptions, and hardware trust boundaries MUST
be documented in the feature spec and checked during review. Cleverness that
reduces reviewability is prohibited in core security paths. Rationale: clean
code is a security control when it makes defects and bad assumptions easier to
find.

## Security Requirements

The firmware MUST treat the RP2350 as a constrained target with limited physical
and hardware trust guarantees. Designs MUST avoid claiming certification or
tamper resistance that the hardware cannot provide. Every feature specification
MUST define:

- the assets being protected
- the attacker capabilities in scope and explicitly out of scope
- the trust boundary between host, transport, firmware, and persistent storage
- the authorization model for each command and state transition
- the behavior on malformed input, interrupted operations, and persistence
  failures

Cryptographic operations MUST use established libraries or reviewed primitives;
roll-your-own cryptography is forbidden. Persistent state design MUST define
anti-rollback, anti-replay, and key-lifecycle handling before implementation.

## Development Workflow & Quality Gates

Every feature plan MUST pass a constitution check before design starts and again
before implementation begins. The check MUST confirm:

- fail-safe behavior is defined for every security-relevant error path
- secret-bearing data structures and zeroization points are identified
- all externally reachable interfaces are justified and minimized
- negative tests and misuse cases are specified alongside success scenarios
- release-build and review expectations are captured for the feature

Tasks MUST include the work needed for malformed-input handling, abuse-case
tests, interface hardening, and documentation updates when the feature changes a
security boundary. Code review for security-sensitive changes MUST verify that
the implementation matches the spec, the plan, and these principles; review is
not complete when only the code compiles.

## Governance

This constitution overrides convenience-driven local practices for this
repository. Amendments require a written rationale, an explicit semantic version
decision, and updates to any affected planning templates in the same change.
MAJOR versions redefine or remove a governing principle. MINOR versions add a
principle, add a mandatory section, or materially expand obligations. PATCH
versions clarify wording without changing behavioral expectations.

Compliance MUST be checked during feature specification, implementation planning,
task generation, and code review. Any justified exception MUST be recorded in
the feature plan's Complexity Tracking section with the simpler alternative that
was rejected and the security reason it was insufficient.

**Version**: 1.0.0 | **Ratified**: 2026-04-01 | **Last Amended**: 2026-04-01
