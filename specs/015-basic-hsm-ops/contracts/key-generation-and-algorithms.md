# Contract: Key Generation and Algorithm Discovery

## Purpose

Define how operators discover supported algorithms and generate managed keys.

## Operator-Facing Capabilities

- list supported algorithms
- generate a symmetric key
- generate an `Ed25519` signing keypair
- inspect generated key metadata

## Required Behavior

- The device must return a bounded, readable list of supported algorithm names,
  key kinds, and allowed operations.
- Key generation must require the correct authenticated role and valid device
  lifecycle state.
- Generated keys must be recorded with explicit algorithm, key kind, usage
  policy, origin, and lifecycle metadata.
- Unsupported algorithms must be denied explicitly.

## Initial Algorithm Set for `015`

| Algorithm | Key Kind | Allowed Operations |
| --- | --- | --- |
| `chacha20poly1305` | symmetric | `generate`, `encrypt`, `decrypt` |
| `ed25519` | asymmetric-signing | `generate`, `sign`, `verify` |
| `p256` | asymmetric-signing-public`*` | `verify` only |

`*` `p256` remains a verification-only public path in this feature. It is not a
generated private-key algorithm in `015`.

## Denial Semantics

- unknown algorithm -> validation denial
- unsupported algorithm -> policy denial
- wrong role or session -> authorization denial
- wrong lifecycle state -> state denial
- exhausted key slots -> bounded capacity denial
