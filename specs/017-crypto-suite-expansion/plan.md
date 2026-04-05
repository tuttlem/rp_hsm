# Implementation Plan: Broadened Crypto Suite

**Branch**: `017-crypto-suite-expansion` | **Date**: 2026-04-05 | **Spec**: [spec.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/spec.md)
**Input**: Feature specification from `/specs/017-crypto-suite-expansion/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

Broaden the HSM crypto surface from “basic operations” into a more deployable
operator suite by adding four coherent capabilities: a supported sender-side
workflow for `x25519-chacha20poly1305` recipient encryption, managed
`HMAC-SHA-256` authentication, managed `P-256` ECDH plus `HKDF-SHA-256`
derivation, and policy-bound wrapped key export that complements the existing
wrapped import path. The goal is more operator choice without turning the device
into an unbounded crypto toolbox.

## Technical Context

**Language/Version**: Rust 2024  
**Primary Dependencies**: `rp235x-hal`, `heapless`, `serialport`, `p256`, `x25519-dalek`, `hkdf`, `sha2`, `chacha20poly1305`, `aes-gcm`, plus reviewed MAC/key-wrap crates if selected during implementation  
**Storage**: RP2350 flash-backed persistent key metadata, policy profile, audit journal, firmware update metadata, and key-store records  
**Testing**: `cargo test -p rp_hsm --target x86_64-unknown-linux-gnu`, `cargo test -p host_tools`, `cargo clippy`, bounded live `rphsmtool` regression, and bounded `cargo probe -- --port /dev/ttyACM0` regression  
**Target Platform**: RP2350 RISC-V firmware plus Linux host CLI over USB CDC serial  
**Project Type**: Embedded firmware plus shared protocol library plus CLI client  
**Performance Goals**: bounded single-request interoperability, MAC, derive, and wrapped-export operations with deterministic memory use and practical debug-build execution on device hardware  
**Constraints**: fail-closed state handling, bounded secret buffers, replay-aware privileged commands, no plaintext private-key export, no unconstrained algorithm sprawl, and operator workflows must remain coherent through `rphsmtool`  
**Security Boundaries**: host provides auth proofs, public material, envelopes, associated data, derivation parameters, and export requests; firmware owns managed private keys, managed MAC keys, derived shared secrets, wrapped-export plaintext, policy enforcement, audit, and secret zeroization; USB CDC transport remains untrusted and all inputs must be validated before use  
**Scale/Scope**: one device, fixed-capacity persistent key store, one supported sender interoperability profile, one first managed MAC family, one first key-agreement/derivation family, and one first policy-bound wrapped-export workflow

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

- Fail-safe behavior: malformed sender envelopes, invalid MAC input, wrong
  derivation parameters, wrong key usage, export-policy violations, and replayed
  privileged commands will all deny explicitly.
- Secret lifecycle: managed private keys, MAC keys, shared secrets, HKDF
  intermediate material, plaintext export candidates, and wrapped-export
  plaintext are all in scope for bounded handling and zeroization.
- Interface scope: the new surface is limited to documented sender
  interoperability, MAC/verify, derive, wrapped export, and related metadata or
  discovery commands.
- Negative testing: tampered envelopes, wrong associated data, wrong role, wrong
  usage, wrong lifecycle state, unsupported profile selection, malformed wrapped
  export/import material, and approval-denied export paths are all required.
- Regression validation: the documented `rphsmtool` workflows plus the bounded
  `cargo probe -- --port /dev/ttyACM0` regression are required because the
  firmware and user surface are both changing.

Post-design gate status: PASS

- Research keeps the expansion tied to complete operator stories rather than
  isolated primitives.
- The data model identifies new secret-bearing entities and the public/secret
  boundaries for sender interoperability, derivation, MAC, and wrapped export.
- The contracts and quickstart define both success-path and denial-path
  workflows for every new surface area.
- The feature remains privilege-scoped: no plaintext private-key export and no
  unauthenticated general-purpose crypto helpers are introduced.

## Project Structure

### Documentation (this feature)

```text
specs/017-crypto-suite-expansion/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
└── tasks.md
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
    ├── bin/
    │   ├── probe_protocol.rs
    │   └── rphsmtool.rs
    └── cli/
        ├── args.rs
        ├── commands.rs
        ├── device.rs
        └── output.rs
```

**Structure Decision**: Keep the existing three-crate workspace split.
Implement command/state/codec changes in `protocol`, persist new key metadata
and export-policy state in `firmware`, and expose the supported operator and
integration workflows through `host_tools`.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
