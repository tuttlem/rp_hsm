# Implementation Plan: Secure Command Protocol

**Branch**: `001-secure-command-protocol` | **Date**: 2026-04-01 | **Spec**: [/home/michael/src/embedded/rp_hsm/specs/001-secure-command-protocol/spec.md](/home/michael/src/embedded/rp_hsm/specs/001-secure-command-protocol/spec.md)
**Input**: Feature specification from `/specs/001-secure-command-protocol/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

Define the first production-grade RP2350 HSM command protocol as a versioned,
bounded request/response transport with explicit frame structure, deterministic
parse outcomes, and command authorization metadata. The implementation will add
a transport-agnostic protocol module inside the firmware, keep the initial
command set deliberately small, and treat malformed or out-of-state traffic as
fail-closed denials rather than recoverable convenience cases.

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: Rust edition 2024 (`no_std`)  
**Primary Dependencies**: `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`; existing USB support remains transport scaffolding only  
**Storage**: N/A for persistent storage in this feature; bounded in-memory frame and parser buffers only  
**Testing**: `cargo check`, `cargo clippy`, unit tests for frame parsing/serialization, malformed-input and state-denial integration tests  
**Target Platform**: RP2350 on `riscv32imac-unknown-none-elf`  
**Project Type**: Embedded firmware  
**Performance Goals**: Deterministic single-frame handling with bounded memory, no unbounded parse loops, immediate rejection of invalid input, and response generation within one request cycle  
**Constraints**: `no_std`, static allocation only, single directly connected host, bounded request/response frames, production firmware must not require debug transport, default-deny on unknown or malformed traffic  
**Security Boundaries**: Assets protected are device control flow and future privileged command surfaces; trust boundary exists between untrusted host input and trusted firmware state; in-scope attacker is a hostile host sending malformed, repeated, replayed, or out-of-state requests; out of scope are physical extraction and transport confidentiality guarantees not provided by this feature  
**Scale/Scope**: First protocol version only, small bootstrap command set, transport-agnostic protocol core with one current firmware integration path

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Pass. Invalid frames, unknown versions, out-of-state commands, interrupted
  exchanges, and serializer failures all resolve to explicit denial or safe
  drop behavior with no partial command execution.
- Pass. This feature handles bounded request and response buffers only; no
  credential or key material is introduced, and transient frame buffers are
  cleared after parse/use paths.
- Pass. The externally reachable interface is a single versioned command
  protocol. The initial command set is intentionally minimal and each command
  declares required device/session state.
- Pass. The spec already requires malformed, oversized, replayed, duplicate,
  unauthorized, and out-of-state denial coverage.
- Pass. The feature will rely on release-hardened firmware settings already in
  the repo and add parser tests, integration denial tests, and contract docs.

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
src/
├── main.rs
├── logging.rs
└── protocol/
   ├── mod.rs
   ├── frame.rs
   ├── command.rs
   ├── codec.rs
   ├── parser.rs
   └── state.rs

tests/
├── protocol/
│  ├── frame_roundtrip.rs
│  ├── malformed_input.rs
│  └── state_enforcement.rs
└── contract/
   └── protocol_vectors.rs
```

**Structure Decision**: Use the existing single-crate embedded firmware layout
at `/home/michael/src/embedded/rp_hsm/src` and add a dedicated `protocol/`
module for transport-agnostic protocol logic. Test coverage will be added under
`/home/michael/src/embedded/rp_hsm/tests` as host-side parser and contract
verification, keeping protocol logic reviewable outside the HAL entrypoint.

## Post-Design Constitution Check

- Pass. `research.md`, `data-model.md`, and `contracts/` define fail-safe
  denial behavior for malformed, unsupported, unauthorized, and replay-sensitive
  requests before implementation starts.
- Pass. The design keeps all protocol buffers bounded and transient, with clear
  cleanup expectations and no introduction of long-lived secret material.
- Pass. The interface remains minimal: a bootstrap discovery/status command set
  only, with future privileged families explicitly reserved and denied for now.
- Pass. Negative coverage is embedded directly into the plan and quickstart via
  malformed-input, out-of-state, unknown-command, and replay-policy tests.
- Pass. The plan stays reviewable by isolating the protocol into a dedicated
  module tree and documenting the external contract independently from HAL
  integration details.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
