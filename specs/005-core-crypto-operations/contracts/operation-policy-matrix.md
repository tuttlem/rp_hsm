# Contract: Operation Policy Matrix

## Operation to Role Matrix

| Operation | Public | Bootstrap | Administrator | Recovery | Key Manager | Developer Override |
|-----------|--------|-----------|---------------|----------|-------------|--------------------|
| `GetCryptoCapabilities` | Yes | Yes | Yes | Yes | Yes | Yes |
| `VerifyDetached` | Yes | Yes | Yes | Yes | Yes | Yes |
| `SignDetached` | No | No | No | No | Yes | Yes in developer-mode only |
| `GenerateRandom` | No | No | Yes | No | Yes | Yes in developer-mode only |
| `ImportWrappedKey` | No | No | No | No | Yes | Yes in developer-mode only |

## Operation to Key Policy Matrix

| Operation | Allowed Key Algorithms | Required Key State | Required Usage |
|-----------|------------------------|--------------------|----------------|
| `SignDetached` | `Ed25519` | `Active` | signing bit set |
| `ImportWrappedKey` destination | `Ed25519` in v1 | new key only | reviewed destination mask |
| `ImportWrappedKey` wrapping key | dedicated wrapping key class | `Active` | import/wrap bit set |

Notes:

- `P256` stored keys exist in metadata but are not executable for managed
  signing in v1.
- `Aes256` keys are not general-purpose crypto-service keys in this feature.
- Revoked, destroyed, pending-destroy, degraded, or recovery-required key-store
  states deny all secret-affecting operations.
- Long crypto workflows must tolerate authenticated-session expiry; operator and
  probe tooling should reauthenticate rather than weakening the session policy.

## Input Bounds

| Operation | Bound |
|-----------|-------|
| `SignDetached.message_len` | `1..=128` bytes |
| `VerifyDetached.message_len` | `1..=128` bytes |
| `VerifyDetached.public_key_len` | algorithm-specific fixed length |
| `VerifyDetached.signature_len` | algorithm-specific fixed length |
| `GenerateRandom.requested_len` | `1..=64` bytes |
| `ImportWrappedKey.ciphertext_len` | bounded to fit current frame maximum |

## Fail-Closed Rules

- Unsupported algorithm and key-policy combinations are denied before
  cryptographic execution.
- If the RNG backend is unavailable or health checks fail, `GenerateRandom`
  returns an error and no partial output.
- If wrapped import unwraps but persistence cannot commit the destination key,
  the imported plaintext is cleared and no key is created.
- If a command is interrupted after authorization but before completion, replay
  of the same request counter must still be denied according to the session
  rules from feature `004`.
- If a key-manager or administrator session expires mid-workflow, subsequent
  privileged crypto commands fail with authorization denial until a new session
  is established.
