# Data Model: Asymmetric Encryption Operations

## Entity: Asymmetric Encryption Algorithm Profile

**Purpose**: Describe one supported asymmetric-encryption profile and its valid
operator-visible uses.

**Fields**:

- `algorithm_id`: stable protocol identifier
- `algorithm_name`: human-readable name
- `key_kind`: `asymmetric-decryption`
- `allowed_operations`: generate, encrypt, decrypt
- `public_material_len`: expected recipient public key length
- `envelope_requirements`: ephemeral public key, nonce, ciphertext, tag
- `status`: `enabled` or `unsupported`

**Validation rules**:

- Unsupported asymmetric-encryption profiles must remain discoverable only as
  absent, not as partially usable entries.
- Each enabled profile must map to explicit generate, encrypt, and decrypt
  operations.

## Entity: Managed Asymmetric Decryption Key

**Purpose**: Represent a device-generated asymmetric recipient keypair that can
be used for encryption and private-key decryption.

**Fields**:

- `key_id`: stable persistent identifier
- `origin`: `device-generated`
- `algorithm`: asymmetric-encryption profile reference
- `key_kind`: `asymmetric-decryption`
- `usage_mask`: allowed operations for the key
- `public_material`: exported recipient public material
- `export_policy`: whether public material may be returned
- `lifecycle_state`: active, revoked, destroyed
- `record_revision`: persistent metadata revision

**Validation rules**:

- Asymmetric decryption keys must not be usable for signing or symmetric
  encryption.
- Revoked or destroyed keys must fail closed on encrypt and decrypt.
- Public material may be exported only in the reviewed metadata form; the
  private component must never be exposed.

## Entity: Asymmetric Ciphertext Envelope

**Purpose**: Describe the bounded response material returned from asymmetric
encryption for later decryption.

**Fields**:

- `algorithm`: asymmetric-encryption profile reference
- `key_id`: recipient key reference
- `ephemeral_public_material`: sender ephemeral public bytes
- `nonce`: bounded AEAD nonce bytes
- `ciphertext`: encrypted payload bytes
- `authentication_tag`: integrity tag bytes

**Validation rules**:

- All envelope fields must be present and length-valid for the selected profile.
- Decryption must fail closed if any field is missing, malformed, tampered, or
  mismatched to the key algorithm.

## Entity: Asymmetric Crypto Operation Request

**Purpose**: Represent an authenticated request to generate a recipient key,
encrypt to it, decrypt with it, or inspect asymmetric-encryption capabilities.

**Fields**:

- `session_role`: authenticated actor role
- `algorithm`: selected asymmetric-encryption profile
- `key_id`: managed key reference
- `input_payload`: plaintext for encrypt or envelope for decrypt
- `replay_counter`: per-session freshness material

**Validation rules**:

- Encrypt and decrypt requests must include an explicit algorithm selection.
- Requests must fail closed if replay counters, role, key usage, or lifecycle
  state are invalid.

## Relationships

- One `Asymmetric Encryption Algorithm Profile` may be used by many
  `Managed Asymmetric Decryption Key` records.
- One `Managed Asymmetric Decryption Key` may produce many
  `Asymmetric Ciphertext Envelope` values over its lifetime.
- One `Asymmetric Ciphertext Envelope` references exactly one managed recipient
  key and one asymmetric-encryption profile.

## State Transitions

### Managed Asymmetric Decryption Key

- `generated` -> `active` when persistence succeeds and the key becomes usable
- `active` -> `revoked` when operator policy revokes use
- `active` -> `destroyed` when the key is deleted
- `revoked` -> `destroyed` when final destruction occurs

### Asymmetric Crypto Operation Request

- `received` -> `validated` when framing, auth, algorithm, usage, and lifecycle
  checks pass
- `validated` -> `completed` when the crypto operation succeeds
- `validated` -> `denied` when policy, state, or input checks fail
