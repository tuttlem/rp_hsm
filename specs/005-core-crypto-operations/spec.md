# Feature Specification: Core Crypto Operations

**Feature Branch**: `005-core-crypto-operations`  
**Created**: 2026-04-01  
**Status**: Draft  
**Input**: User description: "Define the core RP2350 HSM cryptographic service surface including signing, verification, random generation, wrapped key handling, and any approved encryption or key agreement operations"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Controlled Use of Managed Keys (Priority: P1)

As an authorized client, I need to invoke approved cryptographic operations
using managed device keys so that sensitive key material remains under device
control.

**Why this priority**: The primary value of the product is performing
cryptographic work without exposing keys directly to the host.

**Independent Test**: Use authorized keys to request supported cryptographic
operations and confirm that the device returns valid results only when policy,
state, and authorization permit the request.

**Acceptance Scenarios**:

1. **Given** a key is active and allowed for a requested operation, **When** an
   authorized client invokes that operation, **Then** the device returns the
   correct result without exposing secret key material.
2. **Given** a key is not permitted for a requested operation, **When** the
   client invokes it, **Then** the device denies the request.

---

### User Story 2 - Trusted Verification and Randomness (Priority: P2)

As a platform integrator, I need a defined set of non-secret cryptographic
services such as verification and random value generation so that the host can
build complete secure workflows around the device.

**Why this priority**: These operations are common building blocks and support
safe integration without widening secret exposure.

**Independent Test**: Request verification and random generation services under
expected and denied conditions and confirm the outcomes match the specification.

**Acceptance Scenarios**:

1. **Given** a verification request is well-formed and authorized, **When** the
   device processes it, **Then** the device returns a clear success or failure
   outcome for the verification result.
2. **Given** a random generation request is allowed, **When** the device
   fulfills it, **Then** the device returns output only within the declared size
   and request rules.

---

### User Story 3 - Restricted Handling of High-Risk Operations (Priority: P3)

As a security reviewer, I need wrapped key handling and any high-risk
cryptographic operation classes to be explicitly bounded so that the service
surface does not accidentally become a general-purpose secret export path.

**Why this priority**: Wrapped import or export operations and advanced crypto
primitives can undermine the product if their business purpose is not tightly
controlled.

**Independent Test**: Attempt wrapped key operations and any restricted
cryptographic services with permitted and denied key classes, confirming that
only explicitly allowed cases succeed.

**Acceptance Scenarios**:

1. **Given** a wrapped key action is allowed by policy, **When** the request is
   authorized and valid, **Then** the device completes only the approved wrapped
   handling outcome.
2. **Given** a wrapped key or other high-risk crypto action is not permitted,
   **When** the client requests it, **Then** the device denies the request
   without exposing protected material.

### Edge Cases

- A request asks for the maximum permitted random output size.
- A cryptographic operation is requested with input that is well-formed but not
  compatible with the referenced key.
- An operation is interrupted after authorization but before completion.
- Multiple allowed operations target the same key in rapid succession.
- An allowed algorithm family is supported for some keys but not for all key
  origins or lifecycle states.

### Security Misuse Cases *(mandatory)*

- An attacker attempts to use a signing key for a non-approved operation.
- An attacker attempts to turn wrapped key handling into an export channel for
  plaintext secrets.
- An attacker floods the device with large or repeated crypto requests to force
  unsafe resource behavior.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST define the approved set of cryptographic operation
  classes exposed by the product.
- **FR-002**: The system MUST require each cryptographic request to reference an
  operation class, an allowed input shape, and an authorized execution context.
- **FR-003**: The system MUST ensure secret key material used for managed
  cryptographic operations remains under device control throughout processing.
- **FR-004**: The system MUST define which key attributes and lifecycle states
  permit each cryptographic operation class.
- **FR-005**: The system MUST provide a random generation service with explicit
  request limits and error outcomes.
- **FR-006**: The system MUST define fail-safe behavior for invalid inputs,
  incompatible key use, interrupted operations, resource exhaustion, and
  dependency failures during cryptographic processing.
- **FR-007**: The system MUST define how plaintext inputs, intermediate values,
  wrapped key material, and other secret-bearing buffers are bounded, protected,
  and destroyed when no longer needed.
- **FR-008**: The system MUST deny cryptographic requests that are not
  explicitly allowed by key policy, authorization state, or supported service
  scope.
- **FR-009**: The system MUST define the allowed business purpose and control
  rules for wrapped key handling and any high-risk operation class exposed by
  the product.

### Security Requirements *(mandatory)*

- **SR-001**: The feature MUST protect device-managed secrets from being exposed
  through ordinary cryptographic service usage.
- **SR-002**: The feature MUST ensure every cryptographic operation is bound to
  explicit authorization and key usage policy rather than inferred host intent.
- **SR-003**: The feature MUST prevent results, errors, or logs from revealing
  more secret-bearing state than the requested operation requires.

### Key Entities *(include if feature involves data)*

- **Cryptographic Operation Request**: A client request to perform a defined
  service such as signing, verification, random generation, or wrapped key
  handling.
- **Operation Policy**: The declared rules that determine whether a key and
  session may perform a given service.
- **Managed Key Reference**: The identifier used to request a cryptographic
  action without exposing the underlying key material.
- **Operation Result**: The bounded output of an approved cryptographic request,
  including success, denial, or validation outcome.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of approved cryptographic operation classes have documented
  input rules, authorization requirements, and denial conditions.
- **SC-002**: 100% of requests that violate key usage policy, lifecycle state,
  or authorization rules are denied.
- **SC-003**: Integration teams can invoke the approved cryptographic services
  without requiring plaintext access to device-managed secret keys.
- **SC-004**: Reviewers can trace every exposed cryptographic service to a clear
  business purpose and explicit policy boundary.

## Assumptions

- Signing, verification, and random generation are core services for the first
  release.
- Encryption, decryption, key agreement, or similar advanced services are
  exposed only if a later product decision confirms their necessity.
- Wrapped key handling exists to support controlled lifecycle workflows, not to
  provide unrestricted key export.
- Algorithm selection and performance tuning are secondary to clear policy and
  predictable service boundaries at the specification stage.

## Security Acceptance Notes

- Acceptance coverage must prove denial for incompatible keys, unauthorized
  operation classes, oversized requests, and restricted wrapped key actions.
- Any claim about cryptographic strength or side-channel resistance must be
  validated separately from this product-surface specification.
- The specification must not imply that an approved operation class is safe for
  all key types unless that relationship is stated explicitly.
