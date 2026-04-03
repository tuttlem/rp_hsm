# Implementation Plan: rphsmtool CLI

**Branch**: `014-rphsmtool-cli` | **Date**: 2026-04-03 | **Spec**: [/home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/spec.md](/home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/spec.md)
**Input**: Feature specification from `/specs/014-rphsmtool-cli/spec.md`

## Summary

Add a Unix-style `rphsmtool` host CLI that discovers compatible RP HSM
devices, supports explicit and implicit device selection, normalizes
authentication/session/protocol behavior behind stable user-facing verbs, and
uses stdin/stdout-safe data flows for capability-aligned operations such as
status inspection, key metadata inspection, and random generation.

## Technical Context

**Language/Version**: Rust stable workspace, aligned with current Cargo workspace  
**Primary Dependencies**: existing `host_tools` crate, shared `protocol` crate, serial-port access crate already used by the probe, CLI argument parsing crate to be selected during implementation  
**Storage**: N/A for CLI-owned durable storage; transient in-memory handling only  
**Testing**: `cargo test`, `cargo clippy`, host-side CLI tests, protocol contract tests, and live hardware probe validation  
**Target Platform**: Linux host environment with attached RP HSM devices over the existing serial transport  
**Project Type**: workspace CLI application plus shared host-side client helpers  
**Performance Goals**: interactive command startup and response handling suitable for shell use; discovery and simple commands should complete in one operator invocation without manual retries under normal device conditions  
**Constraints**: fail closed on ambiguous device selection, keep stdout clean for pipeline data, keep diagnostics on stderr, preserve existing device authorization/replay semantics, no secret-bearing temp files, and no claim of unsupported operations  
**Security Boundaries**: protect device-selection integrity, authenticated-session material, request counters, opaque stdin payloads, and non-public device responses at the host boundary; trust boundary crosses user shell, host CLI, serial transport, firmware protocol engine, and device persistent state; in scope are local misuse, wrong-device targeting, malformed device responses, replay-sensitive host exchanges, and accidental secret leakage through CLI I/O; out of scope are compromised host kernels, physical extraction from the RP2350, and shell-history leakage caused by operator misuse outside documented safe workflows  
**Scale/Scope**: one canonical CLI binary, one discovery path, one default device-resolution policy, and an initial verb set covering discovery, status, random generation, key listing, and key metadata while reserving future verbs for later firmware capabilities

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Fail-safe behavior is defined for every security-relevant error path.
  Pass: ambiguous device selection, unsupported capabilities, malformed device
  responses, expired sessions, and transport failures are required to fail
  closed with non-zero exit status and no partial stdout leakage.
- Secret-bearing data structures, movement, and zeroization points are identified.
  Pass: stdin payloads, session headers, request counters, random output, and
  any future opaque command input are treated as bounded transient buffers with
  explicit stdout/stderr separation and no temp-file requirement.
- Every externally reachable interface is justified, minimized, and privilege-scoped.
  Pass: the feature adds one user-facing CLI surface and constrains it to
  capability-aligned verbs rather than exposing raw protocol framing.
- Negative tests and misuse cases are defined alongside success-path validation.
  Pass: the spec requires missing-device, multi-device, malformed-response,
  unsupported-operation, and expired-session denial coverage.
- Release-build, review, and deployment constraints for this feature are captured.
  Pass: developer-only workflows must remain distinguishable from production CLI
  usage, and the CLI must not imply unsupported security properties.

## Project Structure

### Documentation (this feature)

```text
specs/014-rphsmtool-cli/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── cli-commands.md
│   ├── device-discovery.md
│   └── io-behavior.md
└── tasks.md
```

### Source Code (repository root)

```text
host_tools/
├── Cargo.toml
└── src/
    ├── bin/
    │   ├── probe_protocol.rs
    │   └── rphsmtool.rs
    ├── cli/
    │   ├── args.rs
    │   ├── commands.rs
    │   ├── device.rs
    │   └── output.rs
    └── lib.rs

protocol/
├── src/
│   └── protocol/
│       ├── codec.rs
│       ├── command.rs
│       ├── frame.rs
│       ├── parser.rs
│       └── state.rs
└── tests/

firmware/
└── src/
    ├── main.rs
    └── persistence.rs
```

**Structure Decision**: Keep the feature in the existing workspace, add a real
`rphsmtool` binary and host-side support modules under `host_tools`, reuse the
shared `protocol` crate for frame/command definitions, and avoid firmware
changes except where capability or status behavior must remain aligned with the
CLI contract.

## Complexity Tracking

No constitution exceptions are currently required.
