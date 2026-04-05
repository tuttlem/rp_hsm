# Data Model: Broadened Crypto Suite

## Entity: Crypto Suite Profile

**Purpose**: Represent one reviewed algorithm or workflow profile exposed to
operators and integrators.

**Fields**:

- `profile_id`: stable protocol identifier
- `profile_name`: human-readable name
- `family`: recipient-encryption, key-agreement, MAC, hash, wrapped-export
- `allowed_operations`: documented operator verbs for the profile
- `input_bounds`: maximum supported request sizes
- `output_bounds`: maximum supported response sizes
- `public_interop`: whether the profile has a documented external sender or
  verifier path
- `status`: enabled or unsupported

**Validation rules**:

- Unsupported profiles must be absent or explicitly denied; they must not be
  partially usable.
- Every enabled profile must map to explicit authorization and usage rules.

## Entity: Managed MAC Key

**Purpose**: Represent a device-retained symmetric key used for managed MAC and
  verification workflows.

**Fields**:

- `key_id`: stable persistent identifier
- `origin`: device-generated or wrapped-imported
- `algorithm`: MAC profile reference
- `usage_mask`: allowed operations for the key
- `export_policy`: exportable or non-exportable
- `lifecycle_state`: active, revoked, destroyed
- `record_revision`: persistent metadata revision

**Validation rules**:

- MAC keys must not be usable for signing, recipient decryption, or unrelated
  symmetric encryption.
- Revoked or destroyed keys must fail closed on MAC and verification.

## Entity: Managed Key Agreement Key

**Purpose**: Represent a device-retained private key used for managed key
agreement and bounded derivation workflows.

**Fields**:

- `key_id`: stable persistent identifier
- `algorithm`: key-agreement profile reference
- `public_material`: exported public bytes
- `usage_mask`: derive-only or derive-plus-wrapped-export policy
- `export_policy`: public-only or wrapped-exportable
- `lifecycle_state`: active, revoked, destroyed

**Validation rules**:

- Key-agreement keys must not be usable for signing unless a later reviewed
  feature explicitly allows it.
- Public material may be exported in metadata form; private material must never
  leave the device outside policy-bound wrapped export.

## Entity: Sender Interoperability Envelope

**Purpose**: Describe the bounded ciphertext structure produced outside or
inside the HSM for recipient encryption.

**Fields**:

- `profile`: recipient-encryption profile reference
- `recipient_key_id`: managed recipient key reference
- `ephemeral_public_material`: sender ephemeral public bytes
- `nonce_or_iv`: bounded AEAD nonce bytes
- `ciphertext`: encrypted payload bytes
- `authentication_tag`: integrity tag bytes
- `associated_data`: optional bounded context bytes if the profile supports it

**Validation rules**:

- The envelope must be self-describing enough for fail-closed validation.
- Decryption must deny if the profile, recipient key, field lengths, tag, or
  associated data are mismatched.

## Entity: Derived Output Request

**Purpose**: Represent a bounded operator request to derive output from managed
key agreement material or approved derivation input.

**Fields**:

- `profile`: derivation profile reference
- `key_id`: managed key reference
- `peer_public_material`: external peer public bytes if required
- `context`: bounded derivation context or info bytes
- `requested_len`: bounded output length
- `replay_counter`: per-session freshness material

**Validation rules**:

- Derivation requests must include an allowed profile and a requested output
  length within the documented bound.
- Requests must fail closed for wrong role, wrong usage, malformed peer
  material, or invalid counter state.

## Entity: Wrapped Export Envelope

**Purpose**: Describe the policy-bound export format for moving explicitly
exportable key material between trust domains.

**Fields**:

- `source_key_id`: managed key reference
- `wrapping_profile`: reviewed wrapped-export profile reference
- `wrapped_payload`: encrypted key material bytes
- `integrity_material`: authentication or tag bytes
- `export_metadata`: algorithm, usage, exportability, and lifecycle summary
- `approval_context`: any required policy or approval trace

**Validation rules**:

- Wrapped export must be denied unless the source key is explicitly exportable.
- The envelope must never expose plaintext private-key material.
- Export metadata must be enough for audit and controlled reimport without
  exposing secret bytes.

## Relationships

- One `Crypto Suite Profile` may be referenced by many managed keys and
  operation requests.
- One `Managed Key Agreement Key` may produce many `Derived Output Request`
  results and many `Sender Interoperability Envelope` decrypt operations.
- One `Wrapped Export Envelope` references exactly one managed source key and
  one reviewed wrapping profile.

## State Transitions

### Managed MAC Key / Managed Key Agreement Key

- `generated` -> `active` when persistence succeeds and the key becomes usable
- `active` -> `revoked` when policy revokes use
- `active` -> `destroyed` when the key is deleted
- `revoked` -> `destroyed` when final destruction occurs

### Derived Output Request

- `received` -> `validated` when auth, profile, bounds, and key-policy checks
  pass
- `validated` -> `completed` when the bounded derivation succeeds
- `validated` -> `denied` when input, policy, or state checks fail

### Wrapped Export Envelope

- `requested` -> `approved` when policy and approval checks pass
- `approved` -> `sealed` when wrapped export succeeds
- `requested` -> `denied` when policy, lifecycle, or approval checks fail
