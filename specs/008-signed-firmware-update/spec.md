# Feature Specification: Signed Firmware Update

**Feature Branch**: `008-signed-firmware-update`  
**Created**: 2026-04-01  
**Status**: Draft  
**Input**: User description: "Define signed firmware update and recovery for the RP2350 HSM including version enforcement, rollback policy, interrupted update handling, and update authorization"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Authorized Firmware Change (Priority: P1)

As a device owner, I need firmware updates to require approved authorization and
trusted update material so that the device does not accept arbitrary software.

**Why this priority**: Update control is a direct trust boundary for the entire
product.

**Independent Test**: Attempt firmware updates using approved and unapproved
update packages and confirm that only authorized trusted updates are accepted.

**Acceptance Scenarios**:

1. **Given** an authorized update request with approved firmware material,
   **When** the device evaluates the update, **Then** it accepts the update and
   transitions through the documented update path.
2. **Given** an update request is unauthorized or the update material is not
   trusted, **When** the device evaluates it, **Then** the device denies the
   update and keeps the current trusted firmware state.

---

### User Story 2 - Protected Version Progression (Priority: P2)

As a security reviewer, I need version progression and rollback behavior to be
explicit so that old or unsafe firmware cannot silently be restored.

**Why this priority**: Version control is essential to preserving security fixes
and preventing rollback attacks.

**Independent Test**: Attempt updates to older, equal, and newer firmware
states, verifying that the device accepts or denies each according to documented
version policy.

**Acceptance Scenarios**:

1. **Given** a firmware package does not satisfy the version progression rules,
   **When** an update is attempted, **Then** the device denies the request.
2. **Given** a firmware package satisfies the version policy, **When** an update
   is performed, **Then** the device records and enforces the new accepted
   firmware state.

---

### User Story 3 - Safe Recovery from Failed Updates (Priority: P3)

As an operator, I need interrupted or failed updates to leave the device in a
defined recoverable condition so that update failure does not silently bypass
policy or brick the product.

**Why this priority**: Lifecycle safety depends on predictable behavior when an
update goes wrong.

**Independent Test**: Interrupt update workflows at defined points and confirm
that the device enters the documented recovery behavior without running
untrusted firmware.

**Acceptance Scenarios**:

1. **Given** power or connectivity is lost during an update, **When** the device
   restarts, **Then** it enters the documented safe recovery behavior.
2. **Given** an update fails validation after transfer has started, **When** the
   device handles the failure, **Then** it retains or restores only a trusted
   firmware state.

### Edge Cases

- An update package is valid but identical to the currently accepted version.
- The update is authorized but the device lacks sufficient capacity or readiness
  to complete it.
- A recovery attempt is started while the device is already in a restricted
  post-failure state.
- An update request arrives while another sensitive administrative workflow is
  active.
- An authorized operator loses session authority during an update process.

### Security Misuse Cases *(mandatory)*

- An attacker attempts to install unauthorized firmware through the update path.
- An attacker attempts to roll the device back to an older firmware state.
- An attacker attempts to abuse recovery behavior to bypass update authorization
  or preserve an untrusted image.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST require explicit authorization before beginning a
  firmware update workflow.
- **FR-002**: The system MUST accept only firmware update material that meets
  the product's trust requirements.
- **FR-003**: The system MUST define version progression rules, including when a
  firmware image is considered older, equal, or newer than the accepted state.
- **FR-004**: The system MUST deny firmware changes that violate the defined
  version or rollback policy.
- **FR-005**: The system MUST define the device states and transitions used for
  update, post-update validation, and recovery.
- **FR-006**: The system MUST define fail-safe behavior for interrupted updates,
  failed validation, invalid authorization, storage failures, and incomplete
  recovery actions.
- **FR-007**: The system MUST define how update packages, validation context,
  and any secret-bearing transitional data are bounded, protected, and destroyed
  when no longer needed.
- **FR-008**: The system MUST ensure the device runs only firmware states that
  satisfy the documented trust and recovery rules.
- **FR-009**: The system MUST define how operators recover a device from an
  update failure without bypassing authorization and trust checks.

### Security Requirements *(mandatory)*

- **SR-001**: The feature MUST protect the boundary between authorized trusted
  firmware evolution and unauthorized code execution.
- **SR-002**: The feature MUST ensure rollback resistance is enforced according
  to the documented version policy.
- **SR-003**: The feature MUST prevent update status, errors, or recovery output
  from exposing secrets or hidden bypass paths.

### Key Entities *(include if feature involves data)*

- **Firmware Package**: The update material presented for installation.
- **Accepted Firmware State**: The currently trusted firmware version and status
  recognized by the device.
- **Update Authorization Context**: The approved authority and conditions needed
  to begin or complete an update.
- **Recovery State**: The defined safe condition entered when a firmware update
  cannot complete normally.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of unauthorized or untrusted firmware update attempts are
  denied.
- **SC-002**: 100% of update attempts that violate rollback or version policy
  are denied.
- **SC-003**: Interrupted or failed updates always result in a defined trusted
  or recoverable device state.
- **SC-004**: Reviewers can determine the allowed update, denial, and recovery
  paths from the specification without needing implementation details.

## Assumptions

- Firmware updates are administrative actions and are not available to routine
  clients.
- The product will tolerate safe update denial more readily than unsafe update
  acceptance.
- Recovery exists to restore trusted operation, not to retain unauthorized
  experimental firmware.
- Production update behavior and development flashing behavior are separate
  concepts.

## Security Acceptance Notes

- Acceptance coverage must prove denial for unauthorized, untrusted, rollback,
  and interrupted update cases.
- Any rollback-resistance claim must identify what stored state the device uses
  to distinguish older from acceptable firmware.
- The specification must not imply that the hardware alone guarantees secure
  update without the documented policy and trust checks.
