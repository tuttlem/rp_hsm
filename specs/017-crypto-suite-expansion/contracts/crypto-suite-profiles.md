# Contract: Crypto Suite Profiles

## Goal

Define the reviewed profile set that `rphsmtool` and the host client may expose
for the broadened crypto suite.

## Required Operator-Visible Profiles

- `x25519-chacha20poly1305`
  - operations: public material export, sender-side envelope generation,
    managed decrypt
- `hmac-sha256`
  - operations: generate, mac, verify-mac
- `p256-ecdh-hkdf-sha256`
  - operations: generate, derive
- `wrapped-export-v1`
  - operations: wrapped export, wrapped import for compatible key classes

## Discovery Rules

- `list-algorithms` or the equivalent discovery command MUST expose only
  profiles that are actually usable on the connected firmware.
- The operator surface MUST not imply that an unsupported profile may work with
  trial-and-error.
- Each exposed profile MUST document:
  - required role
  - required key usage
  - maximum input size
  - maximum output size
  - whether public interoperability is supported

## Denial Semantics

- Unsupported profile selection MUST return a bounded readable denial.
- Wrong usage or wrong key kind MUST return a policy denial, not an ambiguous
  parse failure.
- Profile discovery MUST stay stable between user help text and live device
  behavior.
