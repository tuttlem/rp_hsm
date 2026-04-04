# Feature Specification: Basic HSM Operations

**Feature Branch**: `015-basic-hsm-ops`  
**Created**: 2026-04-04  
**Status**: Draft  
**Input**: User description: "Add the minimum operator-complete HSM crypto surface: internal key generation, symmetric encryption and decryption, asymmetric key generation, detached signing and verification using internally generated keys, explicit algorithm selection and policy, and user-facing CLI flows to create keys, encrypt, decrypt, sign, verify, and inspect supported algorithms so the product supports the basic operations expected of an HSM."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Generate and Use Symmetric Keys (Priority: P1)

An operator provisions the device, creates a symmetric key inside the HSM,
encrypts plaintext with that key, and decrypts the ciphertext back to the
original plaintext without exporting the secret key.

**Why this priority**: Symmetric encryption and decryption are part of the
minimum expected HSM experience for custody and protected data use. Without
this, the product cannot honestly claim the basic encrypt/decrypt workflow.

**Independent Test**: A provisioned device can be fully tested by generating a
new symmetric key, encrypting a known plaintext through `rphsmtool`, then
decrypting the resulting ciphertext and confirming the original plaintext is
recovered exactly.

**Acceptance Scenarios**:

1. **Given** an operational device and an authenticated authorized operator,
   **When** the operator generates a symmetric encryption key inside the HSM and
   encrypts plaintext, **Then** the HSM returns ciphertext and records the key
   with algorithm, usage, and policy metadata.
2. **Given** a ciphertext produced by the HSM under a generated symmetric key,
   **When** the operator requests decryption with the same key and permitted
   policy, **Then** the HSM returns the original plaintext and does not expose
   the key material.

---

### User Story 2 - Generate and Use Asymmetric Keys (Priority: P2)

An operator creates an asymmetric keypair inside the device, signs data with the
private key that never leaves the HSM, and verifies the signature using the
corresponding public material and declared algorithm.

**Why this priority**: A credible HSM must support internally generated
private-key use, not just imported or test-only key material. Detached signing
and verification are the minimum asymmetric workflow required to make the
device useful beyond storage.

**Independent Test**: A provisioned device can be fully tested by generating a
signing keypair, signing a known message through `rphsmtool`, and then
verifying the signature successfully while a modified message or wrong
algorithm fails verification.

**Acceptance Scenarios**:

1. **Given** an operational device and an authenticated authorized operator,
   **When** the operator generates an asymmetric signing keypair and signs a
   message, **Then** the HSM returns a detached signature and retains the
   private key internally.
2. **Given** a message, detached signature, public key, and declared algorithm,
   **When** the operator verifies the signature, **Then** a valid combination is
   accepted and a modified message, wrong key, or wrong algorithm is denied.

---

### User Story 3 - Choose Algorithms and Operate Through the CLI (Priority: P3)

An operator can discover which algorithms the HSM supports, choose an allowed
algorithm when generating or using a key, and perform the basic crypto workflows
through the supported CLI without guessing hidden protocol details.

**Why this priority**: Even if crypto primitives exist internally, the product
is not usable as an HSM until users can choose supported algorithms, understand
policy limits, and drive the workflows through the supported operator surface.

**Independent Test**: A provisioned device can be fully tested by listing
supported algorithms and key capabilities, generating keys for two allowed
algorithms, using them through the CLI, and confirming unsupported algorithms
or disallowed usages are rejected with bounded errors.

**Acceptance Scenarios**:

1. **Given** an operational device, **When** an operator requests supported
   cryptographic algorithms and usage constraints, **Then** the CLI returns a
   readable list of allowed algorithms, key types, and permitted operations.
2. **Given** an unsupported or disallowed algorithm choice, **When** an
   operator attempts to generate or use a key with it, **Then** the device fails
   closed and the CLI reports that the requested algorithm or usage is not
   supported by policy.

### Edge Cases

- What happens when an operator tries to decrypt with a key that is revoked,
  destroyed, wrong-type, or missing the decrypt usage?
- How does the system handle ciphertexts, nonces, tags, signatures, or key
  parameters that are malformed, truncated, oversized, replayed, or mismatched
  to the declared algorithm?
- What happens when the device is in `factory`, `locked`, `recovery`, or
  `zeroized` state and an operator attempts key generation or crypto use?
- How does the system respond when key generation, encryption, or decryption is
  requested with an unsupported algorithm or policy combination?
- What happens when operators attempt to use asymmetric signing keys for
  decryption or symmetric encryption keys for signing?

### Security Misuse Cases *(mandatory)*

- How does the system respond to malformed, truncated, replayed, or out-of-order
  crypto-operation input?
- What prevents unauthorized use of key generation, encryption, decryption,
  signing, verification, or algorithm-selection flows?
- What secrets or sensitive state could this feature expose, and how is that
  prevented from leaking through the CLI, protocol responses, logs, audit
  records, or error paths?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST allow an authorized operator to generate a new
  symmetric key internally on the device without importing the secret key from
  the host.
- **FR-002**: The system MUST allow an authorized operator to generate a new
  asymmetric signing keypair internally on the device without exporting the
  private key.
- **FR-003**: The system MUST allow an authorized operator to encrypt plaintext
  with an internally managed symmetric key and return bounded ciphertext output.
- **FR-004**: The system MUST allow an authorized operator to decrypt ciphertext
  produced under an allowed symmetric algorithm and recover the original
  plaintext when policy permits.
- **FR-005**: The system MUST allow an authorized operator to sign data with an
  internally generated private key and return a detached signature.
- **FR-006**: The system MUST allow signature verification using declared
  algorithm information and matching public material.
- **FR-007**: The system MUST expose the supported key-generation, encryption,
  decryption, signing, and verification algorithms through the supported
  operator surface.
- **FR-008**: The system MUST require an explicit algorithm selection when
  generating keys or invoking algorithms where multiple supported choices
  exist.
- **FR-009**: The system MUST bind each generated key to metadata describing key
  type, algorithm, permitted usages, lifecycle state, and export policy.
- **FR-010**: The supported operator CLI MUST provide end-user commands to
  generate keys, list supported algorithms, encrypt, decrypt, sign, verify, and
  inspect key metadata without requiring raw protocol framing.
- **FR-011**: The system MUST reject unsupported or policy-disallowed algorithm,
  key-usage, or lifecycle-state combinations explicitly and fail closed.
- **FR-012**: The system MUST define fail-safe behavior for invalid state,
  malformed crypto input, dependency failures, and interrupted key-use
  operations.
- **FR-013**: The system MUST define how secret-bearing data such as plaintext,
  generated keys, intermediate buffers, nonces, and temporary private-key
  material is bounded, protected, and destroyed.

### Security Requirements *(mandatory)*

- **SR-001**: The feature MUST protect generated symmetric keys, generated
  private keys, plaintext submitted for encryption or signing, decrypted
  plaintext, and algorithm-selection policy from unauthorized disclosure across
  the host, transport, firmware, and persistent storage boundaries.
- **SR-002**: Key generation and private-key use MUST require the correct
  authenticated authority, respect replay and policy controls, and deny use from
  disallowed lifecycle or session states.
- **SR-003**: The feature MUST not log or expose secret-bearing plaintext,
  generated key material, raw private keys, or reusable auth material through
  CLI output, debug behavior, audit records, or error messages.

### Key Entities *(include if feature involves data)*

- **Managed Symmetric Key**: A device-generated symmetric secret with algorithm,
  usage policy, lifecycle state, and export restrictions.
- **Managed Asymmetric Keypair**: A device-generated public/private keypair
  where the private component remains internal and the public component may be
  referenced for verification workflows.
- **Crypto Algorithm Profile**: A named supported algorithm plus its valid key
  types, allowed operations, required parameters, and policy restrictions.
- **Crypto Operation Request**: An authenticated request to generate a key,
  encrypt, decrypt, sign, or verify, including algorithm choice, input data, and
  key reference.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A provisioned operator can generate a new symmetric key, encrypt a
  test plaintext, and decrypt it back to the original plaintext through the
  supported CLI in one end-to-end workflow without exporting the key.
- **SC-002**: A provisioned operator can generate a new asymmetric signing
  keypair, sign a test message, and verify the detached signature successfully,
  while a modified message or wrong algorithm fails verification.
- **SC-003**: Supported algorithms and key-usage combinations are discoverable
  through the CLI and unsupported choices are rejected with bounded, readable
  denials in 100% of tested cases.
- **SC-004**: The documented user-facing crypto surface for key generation,
  encrypt/decrypt, sign/verify, and algorithm discovery passes a live hardware
  regression before the feature is signed off.

## Assumptions

- The minimum credible HSM surface for this product now includes symmetric
  encrypt/decrypt, internally generated signing keys, and operator-visible
  algorithm selection; this is no longer treated as a future nice-to-have.
- Detached signing and verification satisfy the asymmetric requirement for this
  feature; public-key encryption and key agreement may remain future work if
  they are explicitly documented as out of scope here.
- Host users will access these workflows through `rphsmtool`, not the
  engineering probe, and the CLI remains the supported operator surface.
- Existing provisioning, session, policy, audit, and update controls remain in
  force and must apply consistently to the new crypto operations.

## Security Acceptance Notes

- Identify which acceptance scenarios prove denial behavior, not just success
  behavior.
- Call out any claimed security property that depends on hardware support
  rather than firmware alone.
- Record any out-of-scope attacker capability explicitly instead of implying
  resistance.
- Identify the documented user-facing surface that must be regression-tested
  before this feature can be signed off.
