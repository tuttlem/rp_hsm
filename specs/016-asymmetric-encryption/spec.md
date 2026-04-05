# Feature Specification: Asymmetric Encryption Operations

**Feature Branch**: `016-asymmetric-encryption`  
**Created**: 2026-04-05  
**Status**: Draft  
**Input**: User description: "The HSM now needs to support assymetric encrpytion operations to be a fully featured HSM. These updates mean firmware updates, rphsmtool user surface updates, and documentation updates."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Encrypt to a Managed Recipient Key (Priority: P1)

An operator provisions the device, generates or selects an internal asymmetric
decryption key, encrypts plaintext for that key through the supported CLI, and
receives ciphertext that can be stored or transported without exposing the
private key.

**Why this priority**: Without an actual asymmetric encryption path, the product
still cannot satisfy the basic expectation that an HSM can protect plaintext by
encrypting to a managed keypair whose private half never leaves the device.

**Independent Test**: A provisioned device can be fully tested by generating an
allowed asymmetric decryption key, encrypting a known plaintext through
`rphsmtool`, and confirming the ciphertext is returned with the declared
algorithm profile and bounded metadata.

**Acceptance Scenarios**:

1. **Given** an operational device and an authenticated authorized operator,
   **When** the operator generates an asymmetric decryption key and encrypts a
   plaintext to that key using a supported asymmetric-encryption profile,
   **Then** the HSM returns ciphertext and records the key with algorithm,
   usage, and policy metadata.
2. **Given** an operational device and a recipient public component derived from
   an internal keypair, **When** the operator requests asymmetric encryption
   using that managed recipient key, **Then** the host receives ciphertext and
   the private key remains internal to the device.

---

### User Story 2 - Decrypt with the Managed Private Key (Priority: P2)

An operator submits ciphertext previously produced for a managed asymmetric
decryption key, and the device returns the original plaintext only when the key,
algorithm, lifecycle state, and policy all permit decryption.

**Why this priority**: Encryption alone is not enough. The HSM must also prove
it can perform the corresponding private-key operation internally and recover
plaintext only under the correct authority and policy.

**Independent Test**: A provisioned device can be fully tested by encrypting a
known plaintext to a managed asymmetric key, decrypting the resulting
ciphertext, and confirming the original plaintext is recovered exactly, while a
malformed, mismatched, or wrong-policy ciphertext is denied.

**Acceptance Scenarios**:

1. **Given** a ciphertext produced under a supported asymmetric-encryption
   profile for a managed key, **When** an authorized operator requests
   decryption with that key, **Then** the HSM returns the original plaintext
   and does not expose private material.
2. **Given** a ciphertext that is malformed, truncated, tampered, replayed,
   targeted at the wrong key, or declared under the wrong algorithm profile,
   **When** decryption is requested, **Then** the HSM fails closed and does not
   return plaintext.

---

### User Story 3 - Choose and Understand Asymmetric Encryption Algorithms (Priority: P3)

An operator can discover which asymmetric-encryption algorithms and key types
the HSM supports, choose an allowed algorithm when generating or using a key,
and perform the workflow entirely through `rphsmtool` without guessing protocol
details or internal key-policy rules.

**Why this priority**: Even if asymmetric encryption exists internally, the
product is not usable or reviewable until operators can discover the supported
profiles, choose one intentionally, and understand why an unsupported choice or
wrong key usage is denied.

**Independent Test**: A provisioned device can be fully tested by listing the
supported asymmetric-encryption profiles, generating keys for allowed profiles,
performing encrypt/decrypt successfully, and confirming unsupported algorithm
names, wrong key usages, or disallowed lifecycle states are rejected with
bounded errors.

**Acceptance Scenarios**:

1. **Given** an operational device, **When** an operator requests the supported
   asymmetric-encryption algorithms and key capabilities, **Then** the CLI
   returns a readable list of supported profiles, key types, and permitted
   operations.
2. **Given** an unsupported, disallowed, or mismatched algorithm profile,
   **When** an operator attempts key generation, encryption, or decryption with
   it, **Then** the device fails closed and the CLI reports that the requested
   algorithm or usage is not supported by policy.

### Edge Cases

- What happens when an operator tries to decrypt with a key that is revoked,
  destroyed, wrong-type, wrong-usage, or in a lifecycle state that forbids
  private-key use?
- How does the system handle malformed, truncated, oversized, replayed, or
  tampered ciphertext envelopes, ephemeral public components, nonces, tags,
  wrapped metadata, or algorithm identifiers?
- What happens when the device is in `factory`, `locked`, `recovery`, or
  `zeroized` state and an operator attempts key generation, encryption, or
  decryption?
- How does the system respond when encryption or decryption is requested with an
  unsupported asymmetric-encryption profile or a profile that mismatches the key
  material?
- What happens when ciphertext created under one managed key is presented to a
  different key id, or when a host attempts to reuse stale replay material in an
  authenticated decrypt request?

### Security Misuse Cases *(mandatory)*

- How does the system respond to malformed, truncated, replayed, or
  out-of-order asymmetric-encryption input and authenticated command framing?
- What prevents unauthorized use of private-key decryption, recipient-key
  generation, or algorithm-selection flows?
- What secrets or sensitive state could this feature expose, and how is that
  prevented from leaking through ciphertext metadata, CLI output, debug
  behavior, audit records, or error paths?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST allow an authorized operator to generate a new
  asymmetric decryption keypair internally on the device without exporting the
  private key.
- **FR-002**: The system MUST allow an authorized operator to encrypt plaintext
  for a managed recipient key using a supported asymmetric-encryption profile
  and return bounded ciphertext output.
- **FR-003**: The system MUST allow an authorized operator to decrypt ciphertext
  previously produced for a managed asymmetric key and recover the original
  plaintext when policy permits.
- **FR-004**: The system MUST expose the supported asymmetric-encryption
  algorithm profiles, recipient-key types, and permitted operations through the
  supported operator surface.
- **FR-005**: The system MUST require an explicit asymmetric-encryption
  algorithm selection when generating keys or invoking encrypt/decrypt where
  multiple supported profiles exist.
- **FR-006**: The system MUST bind each asymmetric-encryption key to metadata
  describing key type, algorithm profile, permitted usages, lifecycle state, and
  export policy.
- **FR-007**: The supported operator CLI MUST provide end-user commands to list
  supported asymmetric-encryption algorithms, generate recipient keys, encrypt,
  decrypt, and inspect key metadata without requiring raw protocol framing.
- **FR-008**: The system MUST permit signature workflows from earlier features
  to coexist with asymmetric-encryption workflows without ambiguous key-usage or
  algorithm-selection behavior.
- **FR-009**: The system MUST reject unsupported or policy-disallowed
  algorithm, key-usage, lifecycle-state, or key-type combinations explicitly and
  fail closed.
- **FR-010**: The system MUST define fail-safe behavior for malformed ciphertext
  envelopes, invalid state, dependency failures, and interrupted encrypt/decrypt
  operations.
- **FR-011**: The system MUST define how secret-bearing data such as submitted
  plaintext, decrypted plaintext, private keys, shared-secret intermediates,
  derived symmetric material, nonces, and temporary buffers are bounded,
  protected, and destroyed.
- **FR-012**: The system MUST update firmware, `rphsmtool`, and documentation
  together so the documented user-facing asymmetric-encryption surface matches
  what the device actually supports.

### Security Requirements *(mandatory)*

- **SR-001**: The feature MUST protect managed private keys, plaintext submitted
  for encryption, decrypted plaintext, and any intermediate shared-secret or
  derived symmetric material from unauthorized disclosure across the host,
  transport, firmware, and persistent-storage boundaries.
- **SR-002**: Recipient-key generation and private-key decryption MUST require
  the correct authenticated authority, respect replay and policy controls, and
  deny use from disallowed lifecycle or session states.
- **SR-003**: The feature MUST not log or expose plaintext, raw private keys,
  reusable decrypt material, or secret-bearing intermediate values through CLI
  output, debug behavior, audit records, or error messages.

### Key Entities *(include if feature involves data)*

- **Managed Asymmetric Decryption Keypair**: A device-generated public/private
  keypair whose private component remains internal and whose public component may
  be used to target encryption.
- **Asymmetric Encryption Algorithm Profile**: A named supported algorithm
  profile including key type, required envelope fields, allowed operations, and
  policy restrictions.
- **Asymmetric Ciphertext Envelope**: The bounded encoded output of an
  asymmetric encryption operation, including the algorithm profile identifier and
  any non-secret metadata required for later decryption.
- **Asymmetric Crypto Operation Request**: An authenticated request to generate
  a recipient key, encrypt to it, decrypt with it, or inspect supported
  asymmetric-encryption capabilities.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A provisioned operator can generate a managed asymmetric
  decryption key, encrypt a test plaintext to it, and decrypt it back to the
  original plaintext through `rphsmtool` in one end-to-end workflow without
  exporting the private key.
- **SC-002**: Malformed, tampered, wrong-key, wrong-algorithm, and
  wrong-lifecycle decrypt attempts are rejected with bounded denials in 100% of
  tested cases and do not return plaintext.
- **SC-003**: Supported asymmetric-encryption profiles and key-usage
  combinations are discoverable through the CLI and unsupported choices are
  rejected with readable bounded errors in 100% of tested cases.
- **SC-004**: The documented user-facing asymmetric-encryption surface for key
  generation, encrypt, decrypt, metadata inspection, and algorithm discovery
  passes a live hardware regression before the feature is signed off.

## Assumptions

- The minimum credible HSM surface for this product now includes asymmetric
  encryption and decryption in addition to the symmetric and signing features
  already delivered.
- This feature covers the first shipping asymmetric-encryption workflow and does
  not require every possible public-key encryption family in one release, as
  long as the supported profile is explicit, documented, and operator-usable.
- Operators will access these workflows through `rphsmtool`, not the
  engineering probe, and the CLI remains the supported operator surface.
- Existing provisioning, session, policy, audit, and update controls remain in
  force and must apply consistently to the new asymmetric-encryption operations.

## Security Acceptance Notes

- Identify which acceptance scenarios prove denial behavior, not just success
  behavior.
- Call out any claimed security property that depends on hardware support
  rather than firmware alone.
- Record any out-of-scope attacker capability explicitly instead of implying
  resistance.
- Identify the documented user-facing surface that must be regression-tested
  before this feature can be signed off.
