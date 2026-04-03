# Quickstart: Secure Command Protocol

## Goal

Validate that protocol v1 can be implemented as a bounded, deterministic,
transport-agnostic command layer inside the RP2350 HSM firmware.

## Prerequisites

- Checkout branch `001-secure-command-protocol`
- Read:
  - `specs/001-secure-command-protocol/spec.md`
  - `specs/001-secure-command-protocol/plan.md`
  - `specs/001-secure-command-protocol/research.md`
  - `specs/001-secure-command-protocol/contracts/protocol-frame.md`
  - `specs/001-secure-command-protocol/contracts/command-catalog.md`

## Implementation Flow

1. Create a dedicated `src/protocol/` module tree for frame definitions,
   command metadata, codec logic, parser logic, and state gating.
2. Add a bounded protocol frame type with explicit request/response variants and
   maximum payload size constants.
3. Implement parsing in ordered stages:
   - frame boundary validation
   - structural validation
   - command lookup
   - state/session eligibility check
   - execution dispatch or denial
4. Implement the bootstrap commands:
   - `GetProtocolVersion`
   - `GetDeviceStatus`
   - `GetCommandCatalog`
5. Ensure reserved families return explicit denial outcomes.
6. Clear or overwrite transient frame buffers after parse and serialization use.

## Verification Flow

1. Run parser unit tests for:
   - valid frame roundtrip
   - invalid length rejection
   - oversized payload rejection
   - unknown version rejection
   - unknown command rejection
2. Run state-enforcement tests for:
   - allowed bootstrap commands
   - unauthorized reserved-family rejection
   - out-of-state command rejection
3. Run project validation:

```bash
cargo check
cargo test --lib --test protocol --test contract --target x86_64-unknown-linux-gnu
cargo clippy --target x86_64-unknown-linux-gnu --lib --test protocol --test contract -- -W clippy::pedantic
```

## Expected Outcome

- The firmware exposes a small, explicit v1 command surface.
- Invalid and unsupported traffic is denied deterministically.
- Later provisioning, authentication, and key-management features can attach to
  the same protocol without redefining framing rules.
