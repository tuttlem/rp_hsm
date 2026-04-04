# Implementation Plan: Basic HSM Operations

**Branch**: `015-basic-hsm-ops` | **Date**: 2026-04-04 | **Spec**: [spec.md](/home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/spec.md)
**Input**: Feature specification from `/specs/015-basic-hsm-ops/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

Add the minimum operator-complete HSM crypto surface on top of the existing
provisioning, session, policy, audit, update, and CLI foundations. This feature
adds device-internal symmetric key generation plus encrypt/decrypt, internal
asymmetric signing-key generation plus detached signing, supported-algorithm
discovery and explicit selection, and `rphsmtool` workflows that let operators
perform those tasks without dropping to raw protocol frames.

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: Rust 2024  
**Primary Dependencies**: `rp235x-hal`, `heapless`, `serialport`, `ed25519-dalek`, `chacha20poly1305`, `sha2`, `rand_core`, `rand_chacha`  
**Storage**: RP2350 flash-backed persistent state and key metadata snapshots  
**Testing**: `cargo test -p rp_hsm --target x86_64-unknown-linux-gnu`, `cargo test -p host_tools`, `cargo clippy`, live `rphsmtool` and `cargo probe` regression  
**Target Platform**: RP2350 RISC-V firmware plus Linux host CLI over USB CDC serial  
**Project Type**: Embedded firmware plus shared protocol library plus CLI client  
**Performance Goals**: bounded single-request crypto operations for operator-driven workflows with deterministic memory use and no unbounded buffering  
**Constraints**: no heap requirement in firmware core paths, fail-closed state handling, bounded plaintext/ciphertext sizes, secrets never logged, replay-aware privileged commands  
**Security Boundaries**: host submits auth proofs, plaintext, ciphertext, and public verification material; firmware owns private keys, symmetric keys, policy enforcement, persistent state, and secret zeroization; USB CDC transport is untrusted and must be fully validated  
**Scale/Scope**: one-device operator workflows, fixed-capacity persistent key store, narrow first shipping algorithm set with explicit discovery and denial for unsupported choices

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

- Fail-safe behavior: generation, encrypt/decrypt, sign, algorithm selection,
  and metadata lookup will deny from invalid lifecycle/session/key-policy
  states and on malformed inputs.
- Secret lifecycle: generated keys, plaintext, decrypted plaintext, nonces, and
  private-key intermediates are in scope for bounded buffer handling and
  zeroization.
- Interface scope: new protocol commands and `rphsmtool` verbs are required, but
  remain limited to key generation, algorithm listing, encrypt/decrypt, sign,
  verify, and metadata/list inspection.
- Negative testing: malformed crypto payloads, wrong algorithm, wrong key type,
  wrong usage, revoked key, wrong lifecycle state, and replay-sensitive auth
  flows are all required.
- Regression validation: live `rphsmtool` regression is required for
  `generate-key`, `list-algorithms`, `sym-encrypt`, `sym-decrypt`, `sign`,
  `verify`, and follow-on `status`/`list-keys` checks.

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
<!--
  ACTION REQUIRED: Replace the placeholder tree below with the concrete layout
  for this feature. Delete unused options and expand the chosen structure with
  real paths (e.g., apps/admin, packages/something). The delivered plan must
  not include Option labels.
-->

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
Implement the command/state/codec changes in `protocol`, persist the resulting
crypto state in `firmware`, and expose the supported operator workflows through
`host_tools`.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |
