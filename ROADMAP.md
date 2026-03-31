# RP2350 HSM Product Roadmap

This roadmap describes the path from the current proof-of-concept firmware to a
complete product. "Complete" does not mean certified tamper resistance. It
means the product has a clearly bounded trust model, disciplined key handling,
minimal attack surface, deterministic behavior, controlled lifecycle
operations, and the tooling required to deploy and operate it responsibly.

The roadmap follows the project constitution in
`.specify/memory/constitution.md`. Each phase assumes fail-safe behavior,
explicit secret lifecycle control, minimized default attack surface, and
mandatory negative testing for security-boundary changes.

## Product Completion Criteria

The product should be considered complete only when all of the following are
true:

- the trust model and security limitations are documented honestly
- the wire protocol is stable and versioned
- provisioning and ownership transfer are defined and testable
- key lifecycle rules are complete and enforced
- authentication and authorization are explicit
- audit behavior exists without exposing secrets
- firmware update and recovery flows are controlled
- host tooling is sufficient for real deployment and operations
- release, hardening, and verification processes are repeatable

## Phase 0: Product Definition

The first phase is to define the product precisely before growing the firmware.

- Define the exact product scope and explicit non-goals.
- Define the threat model, including in-scope and out-of-scope attackers.
- Define operating modes such as factory, provisioned, operational, locked,
  recovery, and zeroized.
- Define the external contract: transport, command families, admin model, and
  client identity model.
- Define the persistence model: what state is stored, what is never stored, and
  what can be recovered.

Exit criteria:

- The repo has a written product definition and threat model.
- Security claims match the actual hardware and firmware boundaries.

## Phase 1: Secure Firmware Foundation

Replace demo behavior with a minimal trusted core.

- Implement a deterministic boot flow with explicit fail-safe states.
- Introduce a structured error model and security state machine.
- Separate development and production build behavior clearly.
- Gate debug interfaces so they are impossible in production images.
- Define memory handling rules for secret-bearing buffers and zeroization.
- Establish internal module boundaries for transport, parser, auth, key store,
  crypto services, and audit.

Exit criteria:

- Demo transport behavior is gone from production paths.
- Boot and fault behavior are explicit, documented, and testable.

## Phase 2: Transport and Command Protocol

Define a real device protocol before implementing sensitive operations.

- Create a versioned wire protocol with framing, length checks, command IDs,
  and status codes.
- Implement strict malformed-input rejection.
- Define session semantics and command authorization boundaries.
- Add replay resistance where the command class requires it.
- Define idempotency rules for management commands.
- Build a host-side reference client and protocol test vectors.

Exit criteria:

- Unknown, malformed, truncated, replayed, and out-of-sequence input is handled
  safely.
- The protocol is specified independently of the firmware implementation.

## Phase 3: Identity, Provisioning, and Device Ownership

Make each device individually ownable and provisionable.

- Define device identity and metadata.
- Define a factory provisioning flow.
- Define the trust bootstrap flow between owner and device.
- Define lock, unlock, and ownership transfer behavior.
- Define recovery and re-provisioning behavior.
- Define secure zeroize behavior.

Exit criteria:

- A new device can move from factory state to owned operational state through a
  documented process.
- Ownership changes and destructive reset are explicit authenticated actions.

## Phase 4: Secure Key Lifecycle

This is the core of the product.

- Define in-device key generation.
- Define key import rules and wrapping behavior.
- Define export policy and exportable key classes.
- Define key metadata: algorithm, usage flags, origin, exportability, and
  lifecycle state.
- Define deletion, revocation, archival, and destruction rules.
- Define persistent key storage format and versioning.
- Define anti-rollback and anti-replay considerations for persisted security
  state.

Exit criteria:

- Every key has typed metadata and a clear lifecycle.
- No operation can use a key outside its declared policy.

## Phase 5: Cryptographic Service Surface

Only add crypto operations after the key model exists.

- Add signing operations.
- Add verification operations.
- Add encryption and decryption only if they are truly in scope.
- Add key agreement only if it is truly in scope.
- Add a random number service.
- Add wrapped key import and export services where policy permits them.
- Add hash, HMAC, or KDF services only when they support real product use
  cases.

Exit criteria:

- Every crypto operation maps to explicit permissions and key usage flags.
- Failure and misuse behavior is defined for each operation.

## Phase 6: Authentication and Authorization

Turn the device into a controlled security service rather than a crypto helper.

- Define admin authentication.
- Define operator or application authentication.
- Define session establishment, expiry, and invalidation.
- Define role separation such as bootstrap, admin, operator, audit-only, and
  recovery roles.
- Define rate limiting, retry policy, and lockout or backoff rules.
- Define freshness and anti-replay rules for privileged commands.

Exit criteria:

- Privileged operations are separated from routine crypto use.
- Every externally reachable command has a documented auth requirement.

## Phase 7: Policy Engine

Policy is what makes the device enforceable in practice.

- Implement key usage policy enforcement.
- Implement role-based access rules.
- Define a per-command authorization matrix.
- Define policy around destructive operations.
- Consider dual control or quorum for sensitive administrative actions.
- Consider additional approval steps for export, recovery, or firmware changes.

Exit criteria:

- Security behavior is driven by explicit policy rather than scattered
  conditionals.
- Sensitive operations always require the correct authority.

## Phase 8: Audit and Observability

Make the product operable without leaking secrets.

- Define a security event model.
- Define an audit log schema and severity levels.
- Define retention behavior for constrained hardware.
- Define host-side audit retrieval.
- Define redaction and "never log" rules.
- Define health and status reporting that does not expose sensitive state.

Exit criteria:

- Administrative and security events can be investigated without debug logs.
- Audit information is useful, minimal, and non-secret.

## Phase 9: Firmware Update and Recovery

A complete product needs controlled lifecycle management.

- Implement signed firmware updates.
- Define version enforcement and rollback policy.
- Define boot verification and image transition behavior.
- Define recovery procedure or recovery image behavior.
- Define interrupted-update handling.
- Define update authorization and audit requirements.

Exit criteria:

- Firmware can be updated without bypassing security boundaries.
- Recovery behavior is explicit and does not silently weaken policy.

## Phase 10: Host Tooling and Integration

The device is not complete without the software around it.

- Build a CLI for provisioning, admin operations, and diagnostics.
- Build a host SDK or a narrowly scoped client library.
- Add protocol conformance tests.
- Add manufacturing and provisioning tools.
- Separate developer-mode tools from production tools.
- Write integration guides and reference operational flows.

Exit criteria:

- Users can deploy and operate the device through supported tooling.
- Operational behavior does not require reading firmware source.

## Phase 11: Hardening and Verification

This phase runs continuously, but it must also exist as explicit work.

- Add malformed-input and parser abuse testing.
- Add persistence corruption tests.
- Add replay, reordering, and authorization bypass tests.
- Add state machine invariant testing.
- Review fault handling and interruption behavior.
- Review side-channel exposure where relevant.
- Verify dependency choices and reproducible build behavior.

Exit criteria:

- Major attack surfaces have abuse-case coverage, not only success-path tests.
- Release readiness is based on evidence and review artifacts.

## Phase 12: Product Completion

The final phase is to close the gap between "feature complete" and "shippable."

- Freeze protocol version `v1`.
- Finalize the supported command set.
- Finalize provisioning and ownership workflows.
- Finalize key lifecycle and policy enforcement.
- Finalize audit behavior and operational guidance.
- Finalize signed update and recovery behavior.
- Finalize production build, release, and verification checklists.
- Finalize user, operator, and administrator documentation.
- Finalize published security limitations and non-goals.

Exit criteria:

- The product can be shipped with stable interfaces, documented limitations, and
  repeatable operational procedures.

## Suggested Epic Order

These are the most sensible first epics to discuss and plan in dependency order:

1. Secure command protocol
2. Device state machine and provisioning
3. Persistent key store
4. Authentication and session model
5. Core crypto operations
6. Policy enforcement
7. Audit trail
8. Signed firmware update
9. Host CLI and integration tooling
10. Hardening and release process

## Planning Notes

The roadmap should be used as the input for future feature specifications, not
as an implementation checklist by itself. Each phase should be split into one or
more feature specs that explicitly define security boundaries, misuse cases,
fail-safe behavior, persistence implications, and verification requirements
before implementation begins.
