# Feature Specification: Broadened Crypto Suite

**Feature Branch**: `017-crypto-suite-expansion`  
**Created**: 2026-04-05  
**Status**: Draft  
**Input**: User description: "broadened encryption suite"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Encrypt To and From External Systems (Priority: P1)

An operator needs to use the HSM with other systems, not just with `rphsmtool`
talking to itself. They need to export public recipient material, produce
standards-bounded sender envelopes outside the HSM, and decrypt those
ciphertexts on the device using the managed private key.

**Why this priority**: The current asymmetric feature proves custody, but it is
not yet enough for real interoperability. Without a supported sender-side path,
the device still behaves like an isolated demo rather than a usable crypto
service.

**Independent Test**: Generate a managed recipient key, retrieve its public
material, encrypt plaintext using the supported sender-side workflow, decrypt it
through the HSM, and confirm tampered or wrong-profile envelopes are denied.

**Acceptance Scenarios**:

1. **Given** an operational device with a managed recipient key, **When** an
   operator retrieves public material and encrypts a message with the supported
   sender workflow, **Then** the device decrypts the resulting envelope back to
   the original plaintext.
2. **Given** a ciphertext envelope for a managed recipient key, **When** the
   envelope is modified or the wrong profile is selected, **Then** the device
   rejects the request without exposing plaintext or key material.

---

### User Story 2 - Derive and Authenticate Data With Managed Keys (Priority: P2)

An operator or integrator needs more than raw encryption and signing. They need
the HSM to derive bounded key material and authenticate data so the device can
participate in higher-level protocols and application-specific trust flows.

**Why this priority**: Derivation and authentication are the next practical
building blocks after encryption and signing. They widen the HSM’s usefulness
without requiring immediate support for every legacy algorithm family.

**Independent Test**: Generate or use an allowed managed key, derive bounded
output with the documented derivation workflow, generate and verify an HMAC over
known input, and confirm unauthorized roles or wrong-usage keys are denied.

**Acceptance Scenarios**:

1. **Given** an authorized operator and a managed key with the right usage,
   **When** they request bounded derivation or authentication output, **Then**
   the device returns the expected result length and enforces usage policy.
2. **Given** a key without the required usage or a session without the required
   role, **When** the operator attempts derivation or authentication,
   **Then** the device denies the request without partial execution.

---

### User Story 3 - Export and Use Wrapped Key Material Safely (Priority: P3)

An operator needs the HSM to move explicitly exportable key material between
trust domains without exposing plaintext private keys. They need a reviewed
wrapped-export workflow that matches the existing custody model and CLI.

**Why this priority**: Broader crypto choice is not only about more algorithms.
It also means operators need controlled key movement for backup, migration, and
interoperability, while preserving the HSM’s custody guarantees.

**Independent Test**: Mark an allowed key as exportable, export it through the
wrapped workflow, reimport it into an authorized context, and confirm
non-exportable or wrong-state keys are denied.

**Acceptance Scenarios**:

1. **Given** a managed key that policy explicitly allows to be wrapped,
   **When** an authorized operator exports it through the wrapped workflow,
   **Then** the device returns only the wrapped envelope and audit-visible
   metadata, not plaintext key material.
2. **Given** a non-exportable key or a missing approval requirement,
   **When** the operator attempts wrapped export, **Then** the device rejects
   the request with a bounded denial and leaves the key state unchanged.

### Edge Cases

- What happens when an external sender produces an envelope with a valid shape
  but an unsupported algorithm profile?
- How does the system behave when a derivation, MAC, or wrapped-export request
  asks for a size above the documented bound?
- What happens when a wrapped export is requested for a revoked, destroyed, or
  recovery-blocked key?
- How does the system behave when sender-generated ciphertext arrives for the
  wrong recipient public material?
- What happens when a caller tries to use one command family with a key whose
  usage flags authorize a different family?

### Security Misuse Cases *(mandatory)*

- How does the system respond to malformed, truncated, replayed, or
  profile-mismatched envelopes, derivation requests, MAC inputs, and wrapped
  export/import material?
- What prevents a caller from using public interoperability helpers to bypass
  managed-key policy, export restrictions, or role requirements?
- What secrets or sensitive state could this feature expose, and how are
  private keys, shared secrets, derived material, MAC keys, and plaintext
  export prevented from leaving the device outside documented wrapped workflows?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST expose a documented supported algorithm/profile list
  that includes the broadened crypto suite available to operators and
  integrators.
- **FR-002**: System MUST support a documented sender-side interoperability
  workflow for producing ciphertext envelopes to a managed recipient key using
  exported public material.
- **FR-003**: System MUST allow authorized operators to decrypt supported
  asymmetric ciphertext envelopes on-device using a managed recipient key.
- **FR-004**: System MUST support bounded managed-key derivation workflows for
  approved profiles and declared usages.
- **FR-005**: System MUST support bounded message authentication workflows for
  approved profiles and declared usages.
- **FR-006**: System MUST support hash and derivation workflows only where the
  operator surface documents the result format, size bounds, and authorization
  expectations.
- **FR-007**: System MUST support policy-bound wrapped export for explicitly
  exportable key classes without exposing plaintext private key material.
- **FR-008**: System MUST continue to support wrapped import in a way that is
  coherent with the broadened wrapped-export surface.
- **FR-009**: Users MUST be able to perform the new workflows through
  `rphsmtool` without constructing raw protocol frames manually.
- **FR-010**: System MUST define per-command and per-key usage rules for sender
  interoperability, derivation, MAC, and wrapped export workflows.
- **FR-011**: System MUST return readable denials for wrong role, wrong
  lifecycle state, wrong key usage, malformed envelope, unsupported profile, and
  export-policy violations.
- **FR-012**: System MUST define fail-safe behavior for invalid state,
  malformed input, and dependency failures.
- **FR-013**: System MUST define how secret-bearing data is bounded, protected,
  and destroyed.

### Security Requirements *(mandatory)*

- **SR-001**: The feature MUST protect managed private keys, shared secrets,
  derived outputs, MAC keys, plaintext payloads, and wrapped-export plaintext as
  protected assets within the device trust boundary.
- **SR-002**: The feature MUST enforce authorization, usage policy, and
  freshness requirements so interoperability helpers cannot be used to bypass
  replay controls, export restrictions, or approval requirements.
- **SR-003**: The feature MUST ensure audit and status surfaces record relevant
  use and denial events without exposing private keys, shared secrets, derived
  material, or plaintext payloads.

### Key Entities *(include if feature involves data)*

- **Algorithm Profile**: A reviewed crypto choice exposed to operators,
  including its name, allowed operations, bounds, and public interoperability
  expectations.
- **Managed Recipient Key**: A device-retained asymmetric private key with
  associated public material, usage flags, export policy, and lifecycle state.
- **Sender Envelope**: A bounded ciphertext structure produced outside or inside
  the HSM for a supported recipient-encryption profile.
- **Derived Output Request**: A bounded request that uses managed key material
  or approved inputs to produce a documented derivation result.
- **Wrapped Export Envelope**: A policy-bound container that carries exportable
  key material without exposing plaintext outside the HSM boundary.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Operators can complete the documented external-sender
  encrypt/decrypt workflow on hardware in one uninterrupted session using only
  the published CLI and documentation.
- **SC-002**: Supported derivation, authentication, and wrapped-export commands
  succeed for approved inputs and fail for disallowed inputs with bounded,
  readable denials in every documented misuse case.
- **SC-003**: The supported algorithm list presented to operators matches the
  real device behavior, with no documented command/profile pair failing in the
  approved happy-path workflow.
- **SC-004**: Hardware regression proves that the broadened crypto suite can be
  exercised end to end through `rphsmtool` and bounded engineering validation
  without falling back to manual protocol construction.

## Assumptions

- The broadened suite should remain policy-bound and operator-usable rather
  than becoming a generic “support everything” crypto toolbox.
- The next expansion should prioritize workflows that make the existing HSM
  more interoperable and deployable before adding legacy algorithm families
  solely for breadth.
- Wrapped export is allowed only for explicitly exportable key classes and does
  not imply plaintext private-key export.
- External-sender interoperability must be documented and tested as a supported
  workflow, whether exposed through `rphsmtool`, the host client library, or
  both.
- RSA, password-oriented derivation, and unconstrained compatibility features
  remain out of scope for this feature unless later product definition work
  raises them explicitly.

## Security Acceptance Notes

- Identify which acceptance scenarios prove denial behavior, not just success
  behavior.
- Call out any claimed security property that depends on hardware support
  rather than firmware alone.
- Record any out-of-scope attacker capability explicitly instead of implying
  resistance.
- Identify the documented user-facing surface that must be regression-tested
  before this feature can be signed off.
