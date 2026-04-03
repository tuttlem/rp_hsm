# Data Model: Core Crypto Operations

## Entity: CryptoCapabilities

- Purpose: public discovery view of the approved cryptographic surface.
- Fields:
  - `service_version` (`u8`)
  - `supported_operations` (`bitset`)
  - `supported_sign_algorithms` (`bitset`)
  - `supported_verify_algorithms` (`bitset`)
  - `max_message_len` (`u16`)
  - `max_signature_len` (`u16`)
  - `max_random_len` (`u8`)
  - `wrapped_import_enabled` (`bool`)
- Validation rules:
  - capability output must never imply support for excluded v1 features
  - production and developer-mode images must expose the same crypto capability
    set

## Entity: CryptoOperationRequest

- Purpose: normalized request for a single crypto command.
- Fields:
  - `operation` (`enum`: `SignDetached`, `VerifyDetached`, `GenerateRandom`, `ImportWrappedKey`)
  - `algorithm` (`enum`)
  - `session_context` (`optional`, required for privileged operations)
  - `payload_len` (`u16`)
  - `payload_bytes` (`bounded byte array`)
- Validation rules:
  - exactly one operation class per request
  - payload size must fit the operation-specific schema
  - unsupported algorithm/operation combinations are denied before execution

## Entity: OperationPolicy

- Purpose: reviewed policy matrix tying operation classes to key state and role.
- Fields:
  - `operation`
  - `required_role`
  - `allowed_device_states`
  - `allowed_key_algorithms`
  - `required_usage_mask`
  - `allow_imported_keys`
  - `allow_generated_keys`
  - `max_input_len`
  - `max_output_len`
- Relationships:
  - evaluated against `ManagedKeyReference`
  - evaluated against active auth/session state from feature `004`
- Validation rules:
  - no operation may execute without an explicit policy entry
  - policy must fail closed if metadata is absent or ambiguous

## Entity: ManagedKeyReference

- Purpose: existing persisted key identity plus crypto capability view.
- Fields:
  - `key_id` (`u8`)
  - `algorithm` (`enum`)
  - `origin` (`enum`)
  - `usage_mask` (`u8`)
  - `export_policy` (`enum`)
  - `lifecycle_state` (`enum`)
  - `record_revision` (`u32`)
- Relationships:
  - loaded from the persistent key store
  - consumed by `SignDetached` and `ImportWrappedKey`
- Validation rules:
  - key must be active
  - requested operation must match algorithm and usage mask
  - destroyed or revoked keys are denied

## Entity: SignRequest

- Purpose: request shape for managed signing.
- Fields:
  - `key_id` (`u8`)
  - `algorithm` (`Ed25519` in v1)
  - `message_len` (`u16`)
  - `message` (`1..max_message_len`)
- Validation rules:
  - requires an authenticated key-manager session
  - message length must be non-zero and <= configured bound
  - only active Ed25519 signing keys with `usage_sign` may execute

## Entity: VerifyRequest

- Purpose: request shape for detached verification.
- Fields:
  - `algorithm` (`Ed25519` or `P256` in v1)
  - `message_len` (`u16`)
  - `message` (`1..max_message_len`)
  - `public_key_len` (`u8`)
  - `public_key` (`bounded byte array`)
  - `signature_len` (`u16`)
  - `signature` (`bounded byte array`)
- Validation rules:
  - request may be public
  - key and signature lengths must match the algorithm-specific contract
  - result must be boolean success or failure, not secret-bearing detail

## Entity: RandomRequest

- Purpose: request shape for random-byte generation.
- Fields:
  - `requested_len` (`u8`)
- Validation rules:
  - `requested_len` must be between `1` and `64`
  - requires an authenticated administrator or key-manager session
  - any backend health or availability failure denies the request

## Entity: WrappedKeyEnvelope

- Purpose: bounded import container for bringing approved key material under
  device control.
- Fields:
  - `wrap_format_version` (`u8`)
  - `wrapping_key_id` (`u8`)
  - `target_algorithm` (`enum`)
  - `target_usage_mask` (`u8`)
  - `target_export_policy` (`enum`)
  - `ciphertext_len` (`u16`)
  - `ciphertext` (`bounded byte array`)
  - `integrity_tag_len` (`u8`)
  - `integrity_tag` (`bounded byte array`)
- Validation rules:
  - import only; no symmetric export twin exists in v1
  - destination key must be marked non-exportable
  - malformed or policy-incompatible envelopes fail closed with no key creation

## Entity: CryptoOperationResult

- Purpose: bounded result returned to the host.
- Fields:
  - `operation`
  - `status`
  - `result_len`
  - `result_bytes`
- Result rules:
  - `SignDetached`: detached signature bytes only
  - `VerifyDetached`: boolean verification outcome only
  - `GenerateRandom`: requested random bytes only on success
  - `ImportWrappedKey`: key-id plus non-secret metadata only
  - denials and errors must not include secret-bearing intermediate material

## Entity: SecretBufferClass

- Purpose: explicit tracking class for zeroization and bounded lifetime.
- Variants:
  - `SigningMessageBuffer`
  - `DecodedPrivateKeyBuffer`
  - `WrappedImportPlaintextBuffer`
  - `RandomOutputBuffer`
- Rules:
  - allocated only for the duration of a single request
  - cleared before response framing completes
  - never logged or copied into persistent state except through approved key
    creation flows

## State Transitions

- `SignDetached`
  - no persistent state change on success
  - no persistent state change on denial
- `VerifyDetached`
  - no persistent state change
- `GenerateRandom`
  - no persistent state change
- `ImportWrappedKey`
  - on success, creates a new `ManagedKeyReference` in the persistent key store
  - on any validation, authorization, unwrap, or persistence failure, no key is
    created and no partial state remains
