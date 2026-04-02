# Implementation Plan: Persistent Key Store

**Branch**: `003-persistent-key-store` | **Date**: 2026-04-02 | **Spec**: [/home/michael/src/embedded/rp_hsm/specs/003-persistent-key-store/spec.md](/home/michael/src/embedded/rp_hsm/specs/003-persistent-key-store/spec.md)
**Input**: Feature specification from `/specs/003-persistent-key-store/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

Define a bounded persistent key store for the RP2350 HSM that keeps key
material, key metadata, and lifecycle state durable across reboot while
rejecting stale, corrupted, partially written, or policy-invalid records. The
implementation will add an append-only flash-backed key-record journal in the
shared `protocol` crate, explicit key lifecycle and policy entities, anti-
rollback freshness tracking tied to device state, and narrow management
commands plus host probe coverage so that key persistence remains reviewable and
fails closed under interruption or corruption.

## Technical Context

**Language/Version**: Rust edition 2024 with `no_std` firmware and host-side Rust tooling  
**Primary Dependencies**: `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing `usb-device`/`usbd-serial` developer transport, and existing workspace cargo tooling  
**Storage**: Internal flash-backed append-only key journal plus compact key directory/index, monotonic store revision metadata, and bounded in-RAM staging buffers for record assembly and zeroization  
**Testing**: `cargo test -p rp_hsm --target x86_64-unknown-linux-gnu`, contract tests for key-store commands and record vectors, corruption/rollback/interrupted-write simulations, and host probe verification of management/status paths  
**Target Platform**: RP2350 on `riscv32imac-unknown-none-elf`, with host verification from Linux development systems  
**Project Type**: Embedded firmware workspace with a shared protocol library and host CLI tooling  
**Performance Goals**: Deterministic O(n) bounded key lookup over a small fixed-capacity store, single-key persistence updates within one administrative request cycle, no heap allocation, and reboot-time store recovery before any protected key use is accepted  
**Constraints**: `no_std`, static allocation only, limited flash endurance and capacity, no hardware-backed tamper resistance claims, secret-bearing buffers must be minimized and zeroized, rollback detection can only rely on firmware-managed freshness evidence rather than secure monotonic hardware, and production images must exclude developer-only inspection or recovery shortcuts  
**Security Boundaries**: Assets protected are persisted private or wrapped key material, key metadata, lifecycle state, usage policy, deletion and revocation state, and freshness evidence; trust boundaries exist between untrusted host commands and trusted firmware state, between transient staging buffers and committed flash records, and between device lifecycle state and key-store availability; in-scope attackers include hostile hosts, malformed metadata, replayed management commands, stale flash images, interrupted writes, and attempts to recover deleted key material from remnants or responses; out of scope are invasive physical extraction, certified anti-tamper guarantees, and backup/escrow systems outside the device  
**Scale/Scope**: One device-local persistent store, a fixed bounded number of persistent keys for v1, one record schema version at launch, support for generated and imported keys, explicit states for active/revoked/pending-destruction/destroyed records, and one freshness anchor tied to the device-managed persistent state

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Pass. The spec requires explicit fail-safe behavior for interrupted writes,
  corruption, rollback, exhaustion, invalid metadata, and destructive actions,
  and the plan keeps those outcomes first-class in the store design.
- Pass. Secret-bearing key material, wrapped import blobs, tombstones, and
  staging buffers are identified as bounded data structures with explicit
  destruction points.
- Pass. The only new external surface is a narrow key-store management/status
  command family with explicit lifecycle and authorization rules; no extra
  transport is introduced.
- Pass. The spec already includes rollback, malformed metadata, and secret
  remnant misuse cases, and the plan adds negative tests for record decode,
  interrupted updates, stale journals, and denied post-destruction use.
- Pass. Release and review expectations are captured around flash safety,
  anti-rollback evidence limits, deterministic recovery, and production build
  exclusion of developer-only inspection paths.

## Project Structure

### Documentation (this feature)

```text
specs/003-persistent-key-store/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│  ├── key-store-commands.md
│  └── key-store-records.md
└── tasks.md
```

### Source Code (repository root)

```text
firmware/
├── Cargo.toml
├── build.rs
└── src/
   ├── logging.rs
   └── main.rs

protocol/
├── Cargo.toml
├── src/
│  ├── lib.rs
│  └── protocol/
│     ├── codec.rs
│     ├── command.rs
│     ├── frame.rs
│     ├── mod.rs
│     ├── parser.rs
│     └── state.rs
└── tests/
   ├── contract.rs
   ├── contract/
   ├── protocol.rs
   └── protocol/

host_tools/
├── Cargo.toml
└── src/bin/
   └── probe_protocol.rs
```

**Structure Decision**: Keep the persistent key-store model, record encoding,
integrity/freshness enforcement, and command gating in the shared
`/home/michael/src/embedded/rp_hsm/protocol` crate so it remains host-testable
and reviewable. The firmware crate will own flash integration and boot-time
store initialization, while `/home/michael/src/embedded/rp_hsm/host_tools` will
extend the existing probe with key-store status and negative-path verification.

## Post-Design Constitution Check

- Pass. The design artifacts define fail-safe outcomes for torn writes,
  exhausted capacity, stale store epochs, invalid metadata, and revoked or
  destroyed key use before implementation begins.
- Pass. `research.md` and `data-model.md` identify secret-bearing flash records,
  in-RAM staging buffers, tombstone handling, wrapped import payloads, and
  explicit zeroization/remnant-clearing expectations.
- Pass. The contracts keep the interface narrow: key registration, listing,
  metadata query, revoke, destroy, and storage status. Operational crypto use
  remains separate and policy-gated.
- Pass. The quickstart and contracts pair success paths with corruption,
  replay, full-store, stale-record, and post-destruction denial checks.
- Pass. The workspace layout preserves a reviewable split between pure
  key-store logic in `protocol`, flash integration in `firmware`, and public
  host verification in `host_tools`.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
