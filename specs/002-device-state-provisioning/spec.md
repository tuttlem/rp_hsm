# Feature Specification: Device State and Provisioning

**Feature Branch**: `002-device-state-provisioning`  
**Created**: 2026-04-01  
**Status**: Draft  
**Input**: User description: "Define the RP2350 HSM device state machine, provisioning workflow, ownership bootstrap, lock, unlock, recovery, and zeroize flows"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Controlled Device Bring-Up (Priority: P1)

As a device owner, I need a newly manufactured device to move through a defined
provisioning flow into operational use so that I can trust who controls it and
what state it is in.

**Why this priority**: Ownership and provisioning determine whether later
authentication, key management, and policy features have a trustworthy base.

**Independent Test**: Start with a factory-state device, complete the defined
provisioning process, and confirm that the device enters operational state only
after all required ownership and initialization steps succeed.

**Acceptance Scenarios**:

1. **Given** a device in factory state, **When** an authorized owner completes
   the provisioning process, **Then** the device records the new ownership state
   and enters the expected operational-ready state.
2. **Given** provisioning is incomplete or invalid, **When** the workflow is
   interrupted or rejected, **Then** the device remains in a safe non-operational
   state and does not expose protected functions.

---

### User Story 2 - Predictable State Enforcement (Priority: P2)

As a platform integrator, I need every device mode and transition to be
explicit so that client behavior and administrative operations are predictable
and reviewable.

**Why this priority**: Undefined state transitions create hidden privilege paths
and make recovery, update, and audit behavior hard to reason about.

**Independent Test**: Attempt valid and invalid transitions among factory,
provisioned, operational, locked, recovery, and zeroized states and confirm
that only approved transitions succeed.

**Acceptance Scenarios**:

1. **Given** a device is in locked state, **When** a normal operational command
   is requested, **Then** the device denies it until the required unlock or
   recovery condition is met.
2. **Given** a device is in operational state, **When** an invalid state change
   is requested, **Then** the device rejects the request and preserves current
   state.

---

### User Story 3 - Safe Recovery and Destruction (Priority: P3)

As a security administrator, I need defined recovery and zeroize flows so that
I can respond to loss of control, failed provisioning, or retirement events
without leaving residual secrets or ambiguous ownership.

**Why this priority**: Recovery and destruction paths are high-risk operations
that must be explicit before the product can be operated responsibly.

**Independent Test**: Trigger recovery and zeroize procedures under expected and
interrupted conditions and confirm that the resulting state matches the defined
ownership and secret-destruction outcomes.

**Acceptance Scenarios**:

1. **Given** a device requires recovery, **When** an authorized recovery
   workflow is completed, **Then** the device enters the documented recovery
   state without restoring unauthorized operational access.
2. **Given** a zeroize request is approved, **When** the device performs the
   destructive action, **Then** the device removes protected ownership and
   secret-bearing state and ends in a documented post-zeroize state.

### Edge Cases

- Provisioning is interrupted after ownership intent is declared but before all
  required steps are finalized.
- A device restarts while transitioning between two security-relevant states.
- A lock or recovery request is repeated after the state has already changed.
- A zeroize operation is requested on an already zeroized or factory-state
  device.
- Ownership transfer is attempted while the device is in a non-transferable
  state.

### Security Misuse Cases *(mandatory)*

- An attacker attempts to move a device into operational state without
  completing provisioning.
- An attacker attempts to bypass lock state by issuing routine commands through
  a previously valid host path.
- An attacker attempts to abuse recovery or zeroize operations to gain
  ownership, destroy auditability, or erase evidence of misuse.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST define a finite set of security-relevant device
  states including factory, provisioned, operational, locked, recovery, and
  zeroized states.
- **FR-002**: The system MUST define the allowed transitions between those
  states and reject any transition that is not explicitly permitted.
- **FR-003**: The system MUST define a provisioning workflow that establishes
  device ownership before operational functions become available.
- **FR-004**: The system MUST ensure incomplete or failed provisioning leaves
  the device in a safe non-operational state.
- **FR-005**: The system MUST define lock, unlock, ownership transfer, recovery,
  and zeroize workflows with explicit entry conditions and outcomes.
- **FR-006**: The system MUST define fail-safe behavior for invalid state,
  interrupted transitions, rejected ownership actions, and persistence failures.
- **FR-007**: The system MUST define how ownership records, recovery context,
  and secret-bearing transitional data are bounded, protected, and destroyed
  when no longer needed.
- **FR-008**: The system MUST ensure operational commands are unavailable unless
  the device is in an allowed state for those commands.
- **FR-009**: The system MUST define the post-zeroize state clearly so that
  ownership, secrets, and permissions are not left ambiguous.

### Security Requirements *(mandatory)*

- **SR-001**: The feature MUST protect the trust boundary between an
  unprovisioned device and an owned operational device by requiring explicit and
  reviewable ownership establishment.
- **SR-002**: The feature MUST ensure that recovery, unlock, and transfer
  workflows cannot silently grant broader privileges than documented.
- **SR-003**: The feature MUST prevent state reporting or administrative
  feedback from exposing secret material or sensitive recovery data beyond what
  is required for safe operation.

### Key Entities *(include if feature involves data)*

- **Device State**: The current security posture of the device, including which
  operations are permitted and which administrative workflows are available.
- **Provisioning Record**: The persistent ownership and initialization outcome
  that proves whether a device has been claimed and prepared for use.
- **Recovery Context**: The approved information and authorization state needed
  to move a device from a restricted condition into a controlled recovery flow.
- **Zeroize Event**: A destructive administrative action that removes protected
  ownership and secret-bearing state and places the device into a defined safe
  state.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of documented device states have defined entry conditions,
  allowed operations, and exit conditions.
- **SC-002**: 100% of invalid state transition attempts are rejected without
  widening device privileges or preserving partial ownership state.
- **SC-003**: A new device can be brought from factory state to operational
  state through a documented workflow without ad hoc operator decisions.
- **SC-004**: Recovery and zeroize procedures produce consistent end states that
  can be verified by operators and reviewers after each invocation.

## Assumptions

- Each device has a single controlling owner at a time for the first product
  release.
- Factory provisioning and field ownership bootstrap are separate moments even
  if they occur close together operationally.
- Zeroize is intended to remove device-controlled secrets and ownership records,
  not to provide forensic retention.
- Recovery is a controlled administrative path, not a convenience shortcut back
  to normal operations.

## Security Acceptance Notes

- Acceptance testing must prove denied transitions as thoroughly as successful
- ones.
- Any claim that state integrity survives power interruption must identify
  whether it depends on persistence guarantees outside this feature alone.
- The specification must not imply physical tamper evidence or secure custody
  guarantees that the platform hardware cannot provide by itself.
