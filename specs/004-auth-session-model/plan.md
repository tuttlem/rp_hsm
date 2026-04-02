# Implementation Plan: Authentication and Session Model

**Branch**: `004-auth-session-model` | **Date**: 2026-04-03 | **Spec**: [/home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/spec.md](/home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/spec.md)
**Input**: Feature specification from `/specs/004-auth-session-model/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

Define an explicit authentication and session model for privileged RP2350 HSM
commands so that unauthenticated transport access never implies administrative
authority. The implementation will add bounded credential records, challenge-
response session establishment, role-scoped command authorization, request
freshness tracking, failure accounting with lockout or backoff, and state-
driven session invalidation while keeping the protocol surface narrow and
reviewable in the shared `protocol` crate.

## Technical Context

**Language/Version**: Rust edition 2024 with `no_std` firmware and host-side Rust tooling  
**Primary Dependencies**: `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing flash persistence backend, and existing `usb-device`/`usbd-serial` developer transport  
**Storage**: Internal flash-backed lifecycle and authentication snapshot data plus bounded in-RAM session state, replay trackers, and zeroized transient authentication buffers  
**Testing**: `cargo test -p rp_hsm --target x86_64-unknown-linux-gnu`, protocol and contract tests for authentication flows and denial paths, rate-limit and replay simulations, `cargo clippy`, and hardware validation with `cargo probe -- --port ...` in `developer-mode`  
**Target Platform**: RP2350 on `riscv32imac-unknown-none-elf`, with host verification from Linux development systems  
**Project Type**: Embedded firmware workspace with a shared protocol library and host CLI tooling  
**Performance Goals**: Deterministic bounded-time access checks on every privileged request, one active authenticated administrative session in v1, bounded challenge and failure bookkeeping, and reboot-time invalidation of stale session artifacts before privileged commands are accepted  
**Constraints**: `no_std`, static allocation only, no dynamic permission graph, no transport confidentiality guarantees from this feature, no production inclusion of developer-mode bypasses, explicit zeroization of credential proofs and session secrets, and fail-closed behavior on persistence or integrity ambiguity  
**Security Boundaries**: Assets protected are credential verifier material, session authority, freshness state, failed-attempt counters, and role-to-command authorization decisions; trust boundaries exist between untrusted host transport and privileged command execution, between persisted authentication policy and transient session state, and between developer-only authority shortcuts and production builds; in-scope attackers include hostile hosts, replay attempts, online guessing, stale or interrupted session flows, and lifecycle-driven authority confusion; out of scope are invasive physical attacks, transport secrecy, and external identity providers  
**Scale/Scope**: One device-local authentication domain, a small fixed role set for v1, one active privileged session plus developer-mode exception, one bounded failure-accounting window, and explicit role mapping for every privileged command family

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Pass. The feature is centered on fail-safe denial for invalid credentials,
  expired sessions, replayed requests, stale challenges, and persistence or
  lifecycle ambiguity.
- Pass. Secret-bearing data is limited to credential verifiers, challenge
  material, session proofs, and replay/freshness artifacts, all of which are
  planned with bounded storage and explicit zeroization.
- Pass. No new transport is introduced. The only new public surface is a narrow
  authentication command family plus session status and invalidation commands,
  all privilege-scoped.
- Pass. The spec already requires abuse and replay handling, and the plan adds
  negative coverage for guessed credentials, expired sessions, duplicate proofs,
  stale counters, and state-driven invalidation.
- Pass. Release and review constraints are captured around developer-mode
  exclusion, deterministic denial semantics, and auditable command-to-role
  mappings.

## Project Structure

### Documentation (this feature)

```text
specs/004-auth-session-model/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│  ├── authentication-commands.md
│  ├── role-command-matrix.md
│  └── session-policy.md
└── tasks.md
```

### Source Code (repository root)

```text
firmware/
├── Cargo.toml
├── build.rs
└── src/
   ├── logging.rs
   ├── main.rs
   └── persistence.rs

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

**Structure Decision**: Keep authentication rules, role-to-command mapping,
challenge parsing, session state transitions, replay protection, and denial
semantics in `/home/michael/src/embedded/rp_hsm/protocol` so they remain host-
testable and reviewable. Use `/home/michael/src/embedded/rp_hsm/firmware` only
for persistence integration and boot-time invalidation of session artifacts, and
extend `/home/michael/src/embedded/rp_hsm/host_tools` with explicit auth/session
probe coverage.

## Post-Design Constitution Check

- Pass. `research.md`, `data-model.md`, and the contracts define explicit fail-
  closed outcomes for invalid credentials, stale challenges, expired sessions,
  repeated failures, lifecycle transitions, and persistence ambiguity.
- Pass. The design identifies all secret-bearing elements: credential verifier
  inputs, challenge nonces, session proof bytes, replay counters, and transient
  request material, with bounded storage and destruction points.
- Pass. The contracts introduce only the minimum new command set needed to
  establish, inspect, and invalidate sessions. Existing lifecycle and key-store
  commands remain separately authorized by role.
- Pass. Quickstart coverage pairs success flows with denial for unauthenticated,
  replayed, expired, insufficient-role, and rate-limited access attempts.
- Pass. The workspace split remains reviewable: pure auth/session logic in
  `protocol`, persistent policy integration in `firmware`, and public hardware
  verification in `host_tools`.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
