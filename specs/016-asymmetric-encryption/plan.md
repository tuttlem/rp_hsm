# Implementation Plan: Asymmetric Encryption Operations

**Branch**: `016-asymmetric-encryption` | **Date**: 2026-04-05 | **Spec**: [spec.md](/home/michael/src/embedded/rp_hsm/specs/016-asymmetric-encryption/spec.md)
**Input**: Feature specification from `/specs/016-asymmetric-encryption/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

Add a real operator-facing asymmetric encryption and decryption workflow on top
of the existing provisioning, session, policy, audit, update, and CLI
foundations. This feature introduces device-internal recipient-key generation,
bounded asymmetric ciphertext envelopes, explicit algorithm discovery and
selection, and `rphsmtool` verbs that let operators encrypt and decrypt data
without exporting the managed private key or constructing raw protocol frames.

## Technical Context

**Language/Version**: Rust 2024  
**Primary Dependencies**: `rp235x-hal`, `heapless`, `serialport`, `p256`, `chacha20poly1305`, `sha2`, plus planned `x25519-dalek` and `hkdf` for the first shipping asymmetric-encryption profile  
**Storage**: RP2350 flash-backed persistent state and key metadata snapshots  
**Testing**: `cargo test -p rp_hsm --target x86_64-unknown-linux-gnu`, `cargo test -p host_tools`, `cargo clippy`, live `rphsmtool` and `cargo probe` regression  
**Target Platform**: RP2350 RISC-V firmware plus Linux host CLI over USB CDC serial  
**Project Type**: Embedded firmware plus shared protocol library plus CLI client  
**Performance Goals**: bounded single-request asymmetric encrypt/decrypt operations for operator-driven workflows with deterministic memory use and no unbounded buffering  
**Constraints**: no heap requirement in firmware core paths, fail-closed state handling, bounded plaintext/ciphertext envelope sizes, secrets never logged, replay-aware privileged commands, and acceptable debug-build performance on MCU hardware  
**Security Boundaries**: host submits auth proofs, plaintext, ciphertext envelopes, and algorithm selections; firmware owns recipient private keys, shared-secret derivation, envelope validation, policy enforcement, persistent state, and secret zeroization; USB CDC transport is untrusted and must be fully validated  
**Scale/Scope**: one-device operator workflows, fixed-capacity persistent key store, one first shipping asymmetric-encryption profile with explicit discovery and denial for unsupported choices

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Fail-safe behavior is defined for every security-relevant error path.
- Secret-bearing data structures, movement, and zeroization points are identified.
- Every externally reachable interface is justified, minimized, and privilege-scoped.
- Negative tests and misuse cases are defined alongside success-path validation.
- Release-build, review, and deployment constraints for this feature are captured.
- Required regression validation is identified for the documented user-facing
  surface and, when applicable, for live hardware behavior.

Pre-design gate status: PASS

- Fail-safe behavior: recipient-key generation, encrypt, decrypt, and algorithm
  selection will deny from invalid lifecycle/session/key-policy states and on
  malformed ciphertext envelopes.
- Secret lifecycle: recipient private keys, submitted plaintext, decrypted
  plaintext, derived shared secrets, AEAD keys, nonces, and temporary envelope
  buffers are in scope for bounded handling and zeroization.
- Interface scope: new protocol commands and `rphsmtool` verbs are required, but
  remain limited to algorithm listing, recipient-key generation, asymmetric
  encrypt/decrypt, and key metadata inspection.
- Negative testing: malformed envelope fields, wrong key type, wrong algorithm,
  wrong usage, wrong lifecycle state, replay-sensitive auth flows, and tampered
  ciphertext cases are all required.
- Regression validation: live `rphsmtool` regression is required for
  `list-algorithms`, `generate-key`, `asym-encrypt`, `asym-decrypt`,
  `get-key-metadata`, and post-operation `status`/`list-keys` checks, plus the
  bounded `cargo probe -- --port /dev/ttyACM0` regression because firmware and
  supported operator behavior are both changing.

Post-design gate status: PASS

- Research selected one bounded asymmetric-encryption profile instead of a broad
  multi-family rollout, which keeps the external interface minimal and
  privilege-scoped.
- The data model identifies the new secret-bearing structures and the envelope
  fields that must be validated and zeroized.
- The contracts and quickstart define both success-path and denial-path
  operator workflows, including malformed and wrong-policy cases.
- The live regression surface is explicit for both `rphsmtool` and
  `cargo probe`, satisfying the constitution’s firmware-affecting signoff rule.

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
firmware/
└── src/
    ├── main.rs
    ├── persistence.rs
    └── logging.rs

protocol/
└── src/protocol/
    ├── command.rs
    ├── codec.rs
    ├── parser.rs
    └── state.rs

protocol/tests/
├── contract/
└── protocol/

host_tools/
└── src/
    ├── client.rs
    ├── bin/rphsmtool.rs
    └── cli/
        ├── args.rs
        ├── commands.rs
        ├── device.rs
        └── output.rs
```

**Structure Decision**: Keep the existing three-crate workspace structure.
Implement command/state/codec changes in `protocol`, persist the resulting key
and envelope metadata changes in `firmware`, and expose the supported operator
workflows through `host_tools`.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
