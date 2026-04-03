# Implementation Plan: Signed Firmware Update

**Branch**: `008-signed-firmware-update` | **Date**: 2026-04-04 | **Spec**: [/home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/spec.md](/home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/spec.md)
**Input**: Feature specification from `/specs/008-signed-firmware-update/spec.md`

## Summary

Add an administrative signed-firmware update path for the RP2350 HSM that uses
an authenticated host workflow, a bounded signed update manifest, explicit
version progression rules, dual-slot staged image state in flash metadata, and
fail-safe recovery behavior for interrupted or invalid updates. The design keeps
developer flashing separate from production update logic and requires update
authorization, signature verification, and anti-rollback checks before a new
image is marked bootable.

## Technical Context

**Language/Version**: Rust stable workspace, embedded `no_std` firmware on RP2350 and `std` host tooling  
**Primary Dependencies**: existing workspace crates (`protocol`, `host_tools`, `firmware`), RP235x HAL, current serial host tooling, reviewed signature-verification crate for update manifests, existing flash persistence layer  
**Storage**: reserved on-device flash for persisted lifecycle/key/audit state plus new firmware-update metadata and inactive image slot metadata  
**Testing**: `cargo test`, contract/protocol test suites, `cargo clippy`, host CLI regression checks, live `rphsmtool` and `probe_protocol` hardware validation  
**Target Platform**: RP2350 RISC-V firmware with Linux/macOS-style host CLI over USB CDC in developer mode  
**Project Type**: embedded firmware + shared protocol crate + Unix-style CLI  
**Performance Goals**: bounded update control-plane operations, deterministic boot-selection decisions, host transfer/review flows that fit within current serial admin workflow  
**Constraints**: fail closed on invalid signature/version/state, bounded manifest and chunk sizes, no secret-bearing update buffers retained after use, interrupted update must never boot untrusted firmware, production update path must stay separate from developer flashing  
**Security Boundaries**: assets include bootable firmware trust state, accepted firmware version floor, signing trust anchor, update authorization context, staged image metadata, and recovery state; trust boundaries are host CLI vs firmware, transport vs authenticated command layer, active boot image vs inactive staged image, and persisted update metadata vs transient transfer buffers; in scope are unauthorized update attempts, rollback attempts, interrupted writes, stale approval/session use, and ambiguous restore after power loss; out of scope are physical invasive attacks and hardware root-of-trust claims the RP2350 cannot honestly provide  
**Scale/Scope**: one device, one active trusted firmware lineage, one staged inactive image slot in v1, CLI-managed update/recovery flows for administrative operators only

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Pass: fail-safe behavior is required for invalid signatures, invalid authorization, version rollback, interrupted writes, ambiguous boot metadata, and failed recovery.
- Pass: secret-bearing and trust-bearing data are identified separately; update manifests and signatures are non-secret, but authorization proofs, session tokens, and any transitional package buffers remain bounded and cleared after use.
- Pass: externally reachable interfaces stay narrow: authenticated update commands, status/health visibility, and host tooling support. Developer flashing remains a separate build/deployment path.
- Pass: misuse and negative cases are already in scope: unauthorized updates, rollback attempts, interrupted updates, stale approvals, and recovery abuse.
- Pass: release/deployment constraints are explicit: production update behavior must be distinct from developer-mode flashing and must rely on signed package verification plus version-policy enforcement.

## Project Structure

### Documentation (this feature)

```text
specs/008-signed-firmware-update/
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
├── src/
│   ├── main.rs
│   ├── persistence.rs
│   └── logging.rs
├── rp235x_riscv.x
└── Cargo.toml

protocol/
├── src/
│   └── lib.rs
└── tests/
    ├── contract.rs
    └── protocol.rs

host_tools/
├── src/
│   ├── client.rs
│   ├── lib.rs
│   ├── cli/
│   └── bin/
└── Cargo.toml
```

**Structure Decision**: Keep the existing workspace structure. Shared update
state machines, command metadata, and policy rules belong in `protocol`;
flash-backed update metadata and boot reconciliation belong in `firmware`;
operator-facing update/recovery flows belong in `host_tools`.

## Phase 0: Research

Research resolves these design questions before implementation:

1. Manifest/signature format and verification strategy appropriate for bounded
   embedded firmware updates.
2. Boot-slot and accepted-version metadata strategy that supports anti-rollback
   without overstating hardware guarantees.
3. Interrupted-update and boot-selection behavior that fails closed but remains
   recoverable.
4. Administrative authorization and approval requirements for update and
   recovery actions within the existing policy/session model.

## Phase 1: Design & Contracts

Design outputs for this feature:

- `research.md`: decisions for manifest format, slot strategy, rollback floor,
  and recovery model.
- `data-model.md`: firmware package, update session, boot slot metadata,
  accepted firmware state, and recovery state.
- `contracts/firmware-update-commands.md`: update command surface and payload
  rules.
- `contracts/version-and-recovery-policy.md`: version progression, slot
  activation, and recovery semantics.
- `contracts/update-package-format.md`: signed manifest/package contract.
- `quickstart.md`: operator flow for authorized update, rollback denial, and
  interrupted-update recovery.

## Post-Design Constitution Check

- Pass: the design keeps update trust anchored in explicit manifest verification
  and stored version policy rather than vague hardware claims.
- Pass: transient update buffers and authorization/session material remain
  bounded and explicitly discarded after success, denial, or interruption.
- Pass: the interface remains minimal: authenticated update begin/transfer,
  finalize/activate, recovery status, and host-side package submission.
- Pass: misuse behavior is first-class: unauthorized package, bad signature,
  equal/older version, incomplete transfer, ambiguous restore, and stale
  approval/session all fail closed.
- Pass: developer flashing remains separate from production update semantics and
  must not be used to imply signed-update coverage.

## Complexity Tracking

No constitution violations are required for this feature at planning time.
