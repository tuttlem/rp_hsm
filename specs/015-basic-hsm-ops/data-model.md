# Data Model: Basic HSM Operations

## Entity: Crypto Algorithm Profile

**Purpose**: Describe one supported algorithm and its valid operator-visible
uses.

**Fields**:

- `algorithm_id`: stable protocol identifier
- `algorithm_name`: human-readable name
- `key_kind`: `symmetric` or `asymmetric-signing`
- `allowed_operations`: generation, encrypt, decrypt, sign, verify
- `parameter_requirements`: nonce, tag, public key, or none
- `status`: `enabled` or `unsupported`

**Validation rules**:

- Unsupported algorithms must remain discoverable only as absent, not as
  partially usable entries.
- Each profile must map to at least one explicit allowed operation.

## Entity: Managed Generated Key

**Purpose**: Represent a device-generated key that can be used through the HSM.

**Fields**:

- `key_id`: stable persistent identifier
- `origin`: `device-generated`
- `algorithm`: algorithm profile reference
- `key_kind`: `symmetric` or `asymmetric-signing`
- `usage_mask`: allowed operations for the key
- `export_policy`: whether public material or wrapped export is allowed
- `lifecycle_state`: active, revoked, destroyed
- `record_revision`: persistent metadata revision

**Validation rules**:

- Symmetric keys must not be usable for signing.
- Asymmetric signing keys must not be usable for decryption.
- Revoked or destroyed keys must fail closed on use.

## Entity: Symmetric Ciphertext Record

**Purpose**: Describe the bounded response material returned from symmetric
encryption for later decryption.

**Fields**:

- `algorithm`: algorithm profile reference
- `key_id`: source key reference
- `nonce`: bounded nonce bytes
- `ciphertext`: encrypted payload bytes
- `authentication_tag`: integrity tag bytes

**Validation rules**:

- The nonce and tag lengths must match the selected algorithm profile.
- Decryption must fail closed if any field is missing, malformed, or mismatched
  to the key algorithm.

## Entity: Detached Signature Record

**Purpose**: Represent a signature produced by a managed asymmetric signing key.

**Fields**:

- `algorithm`: algorithm profile reference
- `key_id`: source key reference
- `signature`: bounded detached signature bytes
- `public_key_reference`: returned or derived public verification material

**Validation rules**:

- Verification must fail if the algorithm, message, or public material does not
  match.
- The private key must never be exposed as part of this record.

## Relationships

- One `Crypto Algorithm Profile` may be used by many `Managed Generated Key`
  records.
- One `Managed Generated Key` may produce many `Symmetric Ciphertext Record` or
  `Detached Signature Record` values, depending on its kind and usage policy.
- One `Detached Signature Record` must reference exactly one signing algorithm
  profile.

## State Transitions

### Managed Generated Key

- `generated` -> `active` when persistence succeeds and the key becomes usable
- `active` -> `revoked` when operator policy revokes use
- `active` -> `destroyed` when the key is deleted
- `revoked` -> `destroyed` when final destruction occurs

### Crypto Operation Request

- `received` -> `validated` when framing, auth, algorithm, usage, and lifecycle
  checks pass
- `validated` -> `completed` when the crypto operation succeeds
- `validated` -> `denied` when policy, state, or input checks fail
