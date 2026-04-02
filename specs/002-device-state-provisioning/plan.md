# Implementation Plan: Device State and Provisioning

**Branch**: `002-device-state-provisioning` | **Date**: 2026-04-02 | **Spec**: [/home/michael/src/embedded/rp_hsm/specs/002-device-state-provisioning/spec.md](/home/michael/src/embedded/rp_hsm/specs/002-device-state-provisioning/spec.md)
**Input**: Feature specification from `/specs/002-device-state-provisioning/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

Define the RP2350 HSM device lifecycle as a finite, reviewable state machine
that governs ownership bootstrap, state-gated command availability, lock and
recovery behavior, destructive zeroize handling, and a developer-only bad-state
reset path. The implementation will extend the shared protocol crate with
explicit lifecycle entities, persistent provisioning records, transition
guards, and a single `developer-mode` build boundary so that power
interruption, invalid requests, failed persistence, and lab recovery all resolve
to bounded documented states rather than ambiguous partially provisioned modes.
Recovery re-entry into `operational` will use an explicit dedicated
reactivation command rather than reusing initial provisioning entry semantics.

## Technical Context

**Language/Version**: Rust edition 2024 with `no_std` firmware and host-side Rust tooling  
**Primary Dependencies**: `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing `usb-device`/`usbd-serial` transport gated behind `developer-mode`  
**Storage**: Internal flash-backed provisioning record and state journal for durable lifecycle state; bounded in-memory transition workspace and transient authorization buffers  
**Testing**: `cargo test -p rp_hsm --target x86_64-unknown-linux-gnu`, protocol/state-machine contract tests, transition-denial integration tests, persistence-corruption simulations, host probe verification for state-reporting commands  
**Target Platform**: RP2350 on `riscv32imac-unknown-none-elf`, with host verification from Linux development systems  
**Project Type**: Embedded firmware workspace with shared protocol library and host CLI tooling  
**Performance Goals**: Deterministic state transition evaluation in one request cycle, constant bounded memory per workflow step, single-record persistence updates, and reboot recovery that resolves to a documented safe state before accepting privileged commands  
**Constraints**: `no_std`, static allocation only, no claims of physical tamper resistance, provisioning and recovery must fail closed on interrupted flash writes, all development-only transports and reset paths must be compiled out of production images under a single `developer-mode` feature, and operational commands must stay unavailable until ownership bootstrap completes  
**Security Boundaries**: Assets protected are device ownership state, future administrative authority, transition intent, secret-bearing bootstrap material, and the separation between development-only privilege expansion and production behavior; trust boundaries exist between untrusted host commands and trusted firmware state, and between transient in-RAM transition data and persisted provisioning records; in-scope attackers include hostile hosts, repeated/reordered requests, malformed provisioning payloads, power loss during transitions, and attempts to enumerate or invoke developer-only reset in production; out of scope are invasive physical extraction, side-channel resistance beyond reviewed primitives, and tamper evidence the RP2350 cannot provide  
**Scale/Scope**: One device at a time, single owner for v1, one persistent lifecycle record per device, explicit handling for factory, provisioned, operational, locked, recovery, and zeroized states, plus one developer-only reset target and one explicit `developer-mode` build gate

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Pass. The spec already requires fail-safe outcomes for interrupted
  provisioning, invalid transitions, rejected ownership operations, recovery
  reactivation, and persistence failures, and the plan keeps every transition
  explicit.
- Pass. Secret-bearing transition data, ownership bootstrap material, recovery
  context, and zeroization points are called out as bounded lifecycle objects
  rather than implicit buffers.
- Pass. The only new externally reachable surface is the state/provisioning
  command family plus a developer-only reset path, and every operation is
  gated by explicit device state, required authority, and build mode.
- Pass. Success paths are paired with invalid-transition, repeated-request,
  interrupted-write, unauthorized-recovery, invalid reactivation,
  already-zeroized misuse tests, and production-vs-developer-mode reset
  reachability tests.
- Pass. The feature captures release expectations around persistence integrity,
  reboot safety, and reviewable state-machine logic before implementation.

## Project Structure

### Documentation (this feature)

```text
specs/002-device-state-provisioning/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│  ├── provisioning-commands.md
│  └── state-machine.md
└── tasks.md
```

### Source Code (repository root)

```text
firmware/
├── Cargo.toml
├── build.rs
└── src/
   ├── main.rs
   └── logging.rs

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
   │  └── protocol_vectors.rs
   ├── protocol.rs
   └── protocol/
      ├── frame_roundtrip.rs
      ├── malformed_input.rs
      └── state_enforcement.rs

host_tools/
├── Cargo.toml
└── src/bin/
   └── probe_protocol.rs
```

**Structure Decision**: Keep lifecycle and provisioning logic in the shared
`/home/michael/src/embedded/rp_hsm/protocol` crate so state-machine behavior
can be reviewed and tested on the host, then integrate the resulting command
handling in `/home/michael/src/embedded/rp_hsm/firmware/src/main.rs`. Manual
and scripted verification of public state-reporting behavior will continue
through `/home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs`.

## Post-Design Constitution Check

- Pass. `research.md`, `data-model.md`, and the provisioning/state contracts
  define safe rollback or halt outcomes for incomplete transitions, rejected
  authority, interrupted persistence, post-zeroize behavior, explicit recovery
  reactivation, and developer-reset handling.
- Pass. The design identifies durable ownership records, transient
  authorization payloads, recovery tokens, and explicit zeroization boundaries
  before implementation.
- Pass. The external interface remains deliberately narrow: lifecycle commands,
  state reporting, transition results, and a developer-only reset path that is
  excluded from production builds. Operational crypto use remains locked behind
  state checks.
- Pass. The quickstart and contracts embed denied-transition, repeated-request,
  interrupted-reboot, and unauthorized-command verification alongside success
  scenarios.
- Pass. The workspace layout keeps state logic in reviewable Rust modules and
  requires matching protocol contracts, host tests, and firmware gating before
  implementation.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
