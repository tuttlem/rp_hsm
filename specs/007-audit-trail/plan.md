# Implementation Plan: Audit Trail

**Branch**: `007-audit-trail` | **Date**: 2026-04-03 | **Spec**: [/home/michael/src/embedded/rp_hsm/specs/007-audit-trail/spec.md](/home/michael/src/embedded/rp_hsm/specs/007-audit-trail/spec.md)
**Input**: Feature specification from `/specs/007-audit-trail/spec.md`

## Summary

Add a bounded, persisted audit trail and a redacted health-status surface to the
RP2350 HSM. The design uses an append-only, fixed-capacity audit journal stored
in reserved flash, role-scoped retrieval commands, and an explicit non-secret
health view. Security denials, destructive operations, lifecycle transitions,
and reviewed administrative actions become auditable without exposing keys,
proof material, approval secrets, or unrestricted internal state.

## Technical Context

**Language/Version**: Rust stable, workspace with `no_std` firmware and host-side Rust CLI  
**Primary Dependencies**: `heapless`, `usb-device`, `usbd-serial`, existing `protocol` shared crate, host-side `serialport`  
**Storage**: Reserved on-device flash via `firmware/src/persistence.rs`; bounded in-memory staging buffers only  
**Testing**: `cargo test`, `cargo clippy`, host CLI/probe regression, live developer-mode hardware validation  
**Target Platform**: RP2350 RISC-V firmware plus Linux host tooling over USB CDC  
**Project Type**: Embedded firmware + shared protocol library + host CLI/probe  
**Performance Goals**: Audit writes remain bounded per event; retrieval returns bounded pages without blocking normal command handling beyond current single-request loop constraints  
**Constraints**: No secret-bearing log payloads; bounded event size; bounded retrieval page size; fail closed on persistence ambiguity; developer-only observability helpers compiled out of production builds  
**Security Boundaries**: Assets protected are keys, auth proofs, approval artifacts, internal privileged state, and security-relevant event history. Trust boundaries exist between host and device protocol, firmware runtime and flash persistence, public health visibility and privileged audit review, and developer-only versus production command surfaces. Out of scope are tamper-proof immutable logging guarantees and hardware-backed secure time.  
**Scale/Scope**: v1 covers security/admin event classes, paged audit retrieval, retention-overwrite semantics, and health reporting for one device with tightly bounded storage

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Fail-safe behavior is defined for every security-relevant error path.
  Pass: audit write failure, corrupt audit storage, retrieval decoding failure,
  and storage exhaustion all fall back to bounded status/error behavior rather
  than partial or guessed output.
- Secret-bearing data structures, movement, and zeroization points are identified.
  Pass: audit events carry only reviewed non-secret context; temporary retrieval
  pages and encoding buffers are bounded and cleared after use.
- Every externally reachable interface is justified, minimized, and privilege-scoped.
  Pass: only audit retrieval and health-status commands are added; audit review
  is role-scoped and health remains redacted.
- Negative tests and misuse cases are defined alongside success-path validation.
  Pass: denial logging, unauthorized retrieval, overflow, corruption, and
  redaction cases are part of the plan.
- Release-build, review, and deployment constraints for this feature are captured.
  Pass: developer-only helpers stay outside production builds, and audit
  guarantees are documented without overstating tamper resistance.

## Project Structure

### Documentation (this feature)

```text
specs/007-audit-trail/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
└── tasks.md
```

### Source Code (repository root)

```text
protocol/
├── src/protocol/
└── tests/

firmware/
└── src/

host_tools/
├── src/bin/
├── src/cli/
└── src/client.rs
```

**Structure Decision**: Keep audit event definitions, retrieval/status command
contracts, and redaction logic centered in `protocol/src/protocol/`. Persisted
audit state extends `firmware/src/persistence.rs`, while developer validation
and operator access extend `host_tools/src/client.rs`,
`host_tools/src/bin/probe_protocol.rs`, and `host_tools/src/bin/rphsmtool.rs`.

## Complexity Tracking

No constitution violations are required for this feature.
