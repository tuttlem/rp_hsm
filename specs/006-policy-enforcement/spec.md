# Feature Specification: Policy Enforcement

**Feature Branch**: `006-policy-enforcement`  
**Created**: 2026-04-01  
**Status**: Draft  
**Input**: User description: "Define policy enforcement for the RP2350 HSM including per-command authorization, key usage rules, destructive operation controls, and optional dual-control approvals"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Enforced Command Policy (Priority: P1)

As a security administrator, I need command access decisions to be governed by
explicit policy rules so that the device enforces the intended security model
consistently.

**Why this priority**: Policy is the layer that converts roles, sessions, and
key metadata into enforceable product behavior.

**Independent Test**: Attempt a range of commands across different roles,
session states, and key states, confirming that each request is allowed or
denied according to the documented policy matrix.

**Acceptance Scenarios**:

1. **Given** a command is permitted for the current role and device state,
   **When** the request is submitted, **Then** the device allows it.
2. **Given** a command violates the declared policy rules, **When** the request
   is submitted, **Then** the device denies it without partial execution.

---

### User Story 2 - Controlled Destructive Actions (Priority: P2)

As a product owner, I need destructive and high-impact administrative actions to
be governed by stronger policy requirements so that accidental or malicious use
does not bypass the device's safety model.

**Why this priority**: Destructive operations such as zeroize, transfer, and
revocation carry disproportionate risk and require explicit control.

**Independent Test**: Attempt destructive operations with valid and invalid
authority combinations and confirm that only the approved policy path succeeds.

**Acceptance Scenarios**:

1. **Given** a destructive operation requires elevated approval, **When** the
   required approval conditions are not met, **Then** the device denies the
   operation.
2. **Given** the required approval conditions are met, **When** the destructive
   operation is requested, **Then** the device performs the documented action
   and records the policy-governed outcome.

---

### User Story 3 - Reviewable Security Rules (Priority: P3)

As a security reviewer, I need the product's policy rules to be explicit and
auditable so that privileged behavior is not hidden in scattered implementation
logic.

**Why this priority**: Reviewability is essential for maintaining trust as the
command surface expands.

**Independent Test**: Inspect the policy specification and verify that every
security-relevant command and key action maps to a documented rule and denial
condition.

**Acceptance Scenarios**:

1. **Given** a key has usage restrictions, **When** a client requests an action
   outside those restrictions, **Then** the device denies the request because of
   policy.
2. **Given** a reviewer examines a sensitive command, **When** they inspect the
   policy definition, **Then** they can identify the required role, state, and
   approval conditions without inference.

### Edge Cases

- Two policy rules appear to apply to the same command under different states.
- A command would be allowed by role but denied by key usage policy.
- A destructive action is requested after one approval step has been completed
  but before the final approval requirement is satisfied.
- Policy changes occur while sessions are active.
- A command touches multiple managed keys with different policy attributes.

### Security Misuse Cases *(mandatory)*

- An attacker attempts to invoke a command through a role that has only partial
  authority.
- An attacker attempts to use a permitted command to achieve a forbidden effect
  on a restricted key.
- An attacker attempts to exploit ambiguity between state rules and role rules
  to bypass approval controls.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST define policy rules that determine whether each
  command class is allowed or denied.
- **FR-002**: The system MUST evaluate command policy using explicit inputs such
  as role, session state, device state, key state, and any required approval
  conditions.
- **FR-003**: The system MUST define policy rules for managed key usage,
  including which operation classes are permitted for each key context.
- **FR-004**: The system MUST define stronger policy requirements for
  destructive or high-impact administrative operations.
- **FR-005**: The system MUST deny any command or key action that does not meet
  all applicable policy conditions.
- **FR-006**: The system MUST define fail-safe behavior for conflicting rules,
  incomplete approvals, invalid policy references, and dependency failures in
  policy evaluation.
- **FR-007**: The system MUST define how policy-related secret or approval data
  is bounded, protected, and destroyed when no longer needed.
- **FR-008**: The system MUST support review of policy decisions through
  explicit documented rules rather than undocumented host assumptions.
- **FR-009**: The system MUST define how optional dual-control or multi-party
  approval is applied to the operations that require it.

### Security Requirements *(mandatory)*

- **SR-001**: The feature MUST ensure that privileged behavior cannot occur
  unless an explicit policy rule authorizes it.
- **SR-002**: The feature MUST ensure that destructive operations are governed
  by the strongest documented approval path available for that action.
- **SR-003**: The feature MUST prevent policy decision feedback from exposing
  hidden privilege structure, secret approval material, or sensitive key state
  beyond what is necessary for safe denial handling.

### Key Entities *(include if feature involves data)*

- **Policy Rule**: A documented condition set that allows or denies a command or
  key action.
- **Approval Condition**: An additional control requirement for sensitive
  operations, such as elevated authority or multi-party confirmation.
- **Policy Decision**: The resulting allow or deny outcome for a requested
  action after all relevant rules are applied.
- **Protected Action Class**: A command or lifecycle action that requires
  heightened policy controls because of security impact.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of security-relevant command classes map to documented policy
  rules and denial conditions.
- **SC-002**: 100% of destructive operations require the documented elevated
  policy path before execution.
- **SC-003**: 100% of requests that violate role, key, state, or approval rules
  are denied.
- **SC-004**: Reviewers can evaluate policy coverage for all sensitive actions
  without relying on implementation-specific behavior.

## Assumptions

- Policy is enforced inside the device rather than delegated entirely to host
  software.
- The first release will favor explicit, reviewable policy over highly dynamic
  policy customization.
- Multi-party approval may be limited to the most sensitive administrative
  operations.
- Policy denial reasons may be bounded to avoid leaking unnecessary privilege
  detail to untrusted clients.

## Security Acceptance Notes

- Acceptance coverage must prove that denials occur when any one required policy
  condition is missing.
- Any claim of dual-control assurance must identify which operations require it
  and how incomplete approvals are invalidated.
- The specification must not imply that host-side user interfaces can override
  device policy once a request reaches the HSM boundary.
