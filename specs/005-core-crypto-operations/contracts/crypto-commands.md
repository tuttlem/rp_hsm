# Contract: Crypto Commands

## Public Commands

### `GetCryptoCapabilities`

- Purpose: return the reviewed crypto service surface for the current firmware
  version.
- Authorization: public
- Request payload: empty
- Response payload:
  - `service_version` (`u8`)
  - `operation_flags` (`u8`)
  - `sign_algorithm_flags` (`u8`)
  - `verify_algorithm_flags` (`u8`)
  - `max_message_len` (`u16`)
  - `max_signature_len` (`u16`)
  - `max_random_len` (`u8`)
  - `wrapped_import_enabled` (`u8`)

### `VerifyDetached`

- Purpose: verify a detached signature using caller-supplied public material.
- Authorization: public
- Request payload:
  - `algorithm` (`u8`)
  - `message_len` (`u16`)
  - `message`
  - `public_key_len` (`u8`)
  - `public_key`
  - `signature_len` (`u16`)
  - `signature`
- Response payload:
  - `verified` (`u8`): `0x00` false, `0x01` true
- Denial conditions:
  - unsupported algorithm
  - malformed lengths
  - message, key, or signature outside the allowed bound
  - symmetric-key algorithms presented to detached verification

## Privileged Commands

### `SignDetached`

- Purpose: produce a detached signature using a managed device key.
- Authorization: authenticated key-manager session
- Request payload:
  - auth header (`session_id`, `request_counter`)
  - `key_id` (`u8`)
  - `algorithm` (`u8`)
  - `message_len` (`u16`)
  - `message`
- Response payload:
  - `signature_len` (`u16`)
  - `signature`
- Success conditions:
  - key exists and is active
  - key algorithm is supported for managed signing
  - key usage policy permits signing
  - session and replay checks pass
- Denial conditions:
  - unauthorized session
  - incompatible key algorithm or lifecycle state
  - oversized or malformed message
  - backend or persistence ambiguity

### `GenerateRandom`

- Purpose: return bounded random bytes.
- Authorization: authenticated administrator or key-manager session
- Request payload:
  - auth header
  - `requested_len` (`u8`)
- Response payload:
  - `output_len` (`u8`)
  - `random_bytes`
- Success conditions:
  - request length is within `1..=64`
  - RNG backend is healthy and available
- Denial conditions:
  - unauthorized session
  - zero or oversized request length
  - RNG backend failure or health ambiguity
  - expired authenticated session before execution

### `ImportWrappedKey`

- Purpose: import approved wrapped key material into the managed key store.
- Authorization: authenticated key-manager session
- Request payload:
  - auth header
  - `wrap_format_version` (`u8`)
  - `wrapping_key_id` (`u8`)
  - `target_algorithm` (`u8`)
  - `target_usage_mask` (`u8`)
  - `target_export_policy` (`u8`)
  - `ciphertext_len` (`u16`)
  - `ciphertext`
  - `integrity_tag_len` (`u8`)
  - `integrity_tag`
- Envelope notes:
  - v1 uses a 12-byte nonce plus 16-byte AEAD tag packed into the 28-byte
    `integrity_tag` field
  - the associated data string is fixed to `rp_hsm.wrap.v1`
- Response payload:
  - `key_id` (`u8`)
  - `algorithm` (`u8`)
  - `origin` (`u8`)
  - `lifecycle_state` (`u8`)
  - `record_revision` (`u32`)
- Success conditions:
  - wrapping key exists and is authorized for import use
  - envelope format is valid
  - unwrap succeeds and destination policy is allowed
  - persistence commit succeeds
- Denial conditions:
  - unauthorized session
  - malformed envelope
  - unsupported wrap format or target algorithm
  - target export policy not allowed
  - unwrap or integrity validation failure
  - persistence failure

## Explicitly Excluded Commands

- `ExportWrappedKey` (`0x93`): not present in v1
- `Encrypt` (`0x94`): not present in v1
- `Decrypt` (`0x95`): not present in v1
- `DeriveSharedSecret` / key agreement (`0x96`): not present in v1

Unsupported or excluded requests must fail closed with a command or policy
denial rather than partial execution.
