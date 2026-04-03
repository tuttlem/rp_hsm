# Implementation Plan: Core Crypto Operations

**Branch**: `005-core-crypto-operations` | **Date**: 2026-04-03 | **Spec**: [/home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/spec.md](/home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/spec.md)
**Input**: Feature specification from `/specs/005-core-crypto-operations/spec.md`

## Summary

Add a narrowly scoped cryptographic service surface to the RP2350 HSM workspace:
managed Ed25519 signing, bounded detached verification, bounded random-byte
generation, and wrapped key import for approved lifecycle workflows. Keep
high-risk operations fail-closed by default: no plaintext key export, no
general-purpose decrypt or encrypt service, and no key agreement in v1.

## Technical Context

**Language/Version**: Rust 2024 edition, `no_std` firmware on RP2350, host tooling on std Rust  
**Primary Dependencies**: existing `heapless`, `rp235x-hal`, `usb-device`, `usbd-serial`, plus reviewed RustCrypto/signature crates for Ed25519 verification/signing, digest handling, and zeroization-compatible secret containers  
**Storage**: existing flash-backed persistent state in `firmware/src/persistence.rs`; no new database or filesystem layer  
**Testing**: `cargo test -p rp_hsm --target x86_64-unknown-linux-gnu`, contract/protocol suites, host probe validation, firmware `cargo build`, `cargo clippy`  
**Target Platform**: RP2350 RISC-V firmware target with a desktop Linux host probe over developer-mode USB CDC  
**Project Type**: Cargo workspace with embedded firmware crate, shared protocol crate, and host-tools crate  
**Performance Goals**: deterministic single-request execution with bounded payload sizes, no streaming crypto operations, and interactive host latency for one-shot commands rather than throughput optimization  
**Constraints**: `no_std`, static allocation only, fail-closed on RNG/backend failure, bounded secret buffers, no plaintext key export path, no production inclusion of developer-only recovery paths, and no unreviewed custom cryptography  
**Security Boundaries**: protected assets are managed private keys, wrapped import plaintext, RNG output before framing, and intermediate secret buffers; trust boundary runs between host requests, protocol parser, authorization/session state, key store metadata, and firmware persistence; in-scope attackers are malformed-input clients, replaying or unauthorized hosts, and abuse of high-risk crypto commands; out of scope are physical extraction resistance and certification-grade side-channel guarantees from RP2350 hardware  
**Scale/Scope**: one active privileged session, one crypto operation per request, bounded verification/signing input sizes, one wrapped-import path, and explicit denial for unsupported algorithm families and advanced crypto classes

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Pass. Fail-safe behavior is defined around invalid key usage, unsupported
  algorithm requests, RNG/backend failure, malformed wrapped envelopes, and
  interrupted crypto operations.
- Pass. Secret-bearing data structures are limited to managed key material,
  wrapped-import plaintext, RNG output buffers before framing, and transient
  signing inputs; all require bounded lifetime and explicit clearing.
- Pass. Externally reachable interfaces are limited to a small crypto command
  family plus a public capability query; export, decrypt, and key agreement are
  intentionally excluded from v1.
- Pass. Negative and misuse testing is required for incompatible keys,
  oversized inputs, unauthorized use, replay attempts, and wrapped-import abuse.
- Pass. Developer-mode separation, review expectations, and release-build
  exclusions remain required for any lab-only validation hooks.

## Project Structure

### Documentation (this feature)

```text
specs/005-core-crypto-operations/
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
└── src/
    └── protocol/
        ├── command.rs
        ├── codec.rs
        ├── mod.rs
        ├── parser.rs
        └── state.rs

protocol/tests/
├── contract.rs
├── contract/
└── protocol.rs

host_tools/
└── src/
    └── bin/
        └── probe_protocol.rs
```

**Structure Decision**: Keep the existing workspace split. Put crypto command
definitions, request/result codecs, policy enforcement, and operation-state
tracking in `protocol/src/protocol/`. Keep persistence integration in
`firmware/src/`, and extend the existing developer-mode probe in
`host_tools/src/bin/probe_protocol.rs` for live validation.

## Phase 0: Research

- Choose the v1 crypto surface and explicitly reject unsafe scope expansion.
- Choose the authorization and key-policy model for each operation class.
- Choose the RNG and wrapped-import behavior with fail-closed backend rules.
- Choose request-shape limits that fit bounded `heapless` buffers and current
  framing constraints.

## Phase 1: Design & Contracts

- Define operation request/result entities and the per-key capability matrix.
- Define crypto command contracts, public capability discovery, and denial
  semantics.
- Define quickstart validation for managed signing, public verification,
  bounded RNG, wrapped-import approval, and denial cases.
- Update agent context after the design artifacts are written.

## Post-Design Constitution Check

- Pass. The design keeps signing and wrapped-import secret-bearing buffers
  explicit, excludes export, decrypt, and key agreement from v1, and carries
  misuse and negative validation into the contracts and quickstart.

## Complexity Tracking

No constitution violations are expected for this feature.
