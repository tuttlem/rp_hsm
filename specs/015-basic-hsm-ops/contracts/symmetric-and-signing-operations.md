# Contract: Symmetric and Signing Operations

## Purpose

Define the required behavior for encrypt/decrypt and detached sign/verify.

## Symmetric Operations

### Encrypt

- input: key reference, algorithm, plaintext
- output: nonce, ciphertext, authentication tag
- policy: requires a symmetric key with encrypt usage and matching algorithm

### Decrypt

- input: key reference, algorithm, nonce, ciphertext, authentication tag
- output: plaintext
- policy: requires a symmetric key with decrypt usage and matching algorithm

## Signing Operations

### Sign

- input: key reference, algorithm, message
- output: detached signature and bounded public verification reference where
  applicable
- policy: requires an asymmetric signing key with sign usage and matching
  algorithm

### Verify

- input: algorithm, message, public material, detached signature
- output: valid or invalid result
- policy: must reject mismatched algorithm or malformed public material

## Shared Fail-Closed Rules

- malformed plaintext, ciphertext, nonce, tag, or signature inputs are denied
- wrong algorithm or wrong key type is denied
- revoked, destroyed, or wrong-state keys are denied
- no operation may expose raw generated secret key material
