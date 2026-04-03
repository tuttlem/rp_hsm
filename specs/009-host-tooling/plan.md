# Implementation Plan: Host Tooling Consolidation and Integration

**Branch**: `009-host-tooling` | **Date**: 2026-04-04 | **Spec**: [spec.md](/home/michael/src/embedded/rp_hsm/specs/009-host-tooling/spec.md)
**Input**: Feature specification from `/specs/009-host-tooling/spec.md`

## Summary

Consolidate the already-existing host tooling into a clearly supported product
surface by hardening `rphsmtool` as the canonical operator CLI, defining a
stable machine-consumable host integration surface around `host_tools::client`,
improving host-side transport failure handling, and documenting the separation
between operator workflows, engineering validation, and developer-only
utilities.

## Technical Context

**Language/Version**: Rust stable in the existing Cargo workspace  
**Primary Dependencies**: `serialport`, `heapless`, `ed25519-dalek`, `sha2`,
existing `host_tools` CLI/client modules  
**Storage**: N/A on host; local process memory plus stdin/stdout and environment
variables for transient proof input  
**Testing**: `cargo test`, `cargo clippy`, live `rphsmtool` and `probe_protocol`
validation against developer-mode firmware  
**Target Platform**: Linux host environments using `/dev/ttyACM*` serial
devices for RP2350 development and operator workflows  
**Project Type**: CLI plus reusable host-side client library inside the
workspace  
**Performance Goals**: Low-latency command execution for bounded serial
operations; no throughput-sensitive bulk host processing beyond existing framed
device exchanges  
**Constraints**: Must preserve device-side policy enforcement, keep stdout
machine-usable, fail clearly on busy/missing device nodes, and avoid exposing
developer-only tooling as default product behavior  
**Security Boundaries**: Device remains the sole authority for provisioning,
authorization, policy, key use, audit, and update decisions; host tooling may
format, transport, and present results but must not bypass device policy or
invent privileged behavior. Host transient proofs and command payloads must stay
bounded and out of logs.  
**Scale/Scope**: One workspace CLI (`rphsmtool`), one engineering probe
(`probe_protocol`), one reusable host client module (`host_tools::client`), and
documentation/install guidance for single-device and small multi-device operator
environments

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Fail-safe behavior is defined for host-side transport contention, interrupted
  workflows, partial command completion, and client/library version mismatch.
- Secret-bearing host inputs are limited to transient proof material, bounded
  stdin payloads, and update images; these remain outside logs and are cleared
  or dropped after use.
- Every externally reachable host interface is justified: `rphsmtool` for
  operators, `probe_protocol` for engineering validation, and `host_tools`
  client APIs for integrations.
- Negative tests are required for busy device nodes, missing permissions,
  unsupported commands, device denials, and misuse of engineering-only tools.
- Release and support expectations must capture install/run guidance, canonical
  entry points, and the distinction between product and developer workflows.

## Project Structure

### Documentation (this feature)

```text
specs/009-host-tooling/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── cli-surface.md
│   ├── host-client-surface.md
│   └── transport-and-packaging.md
└── tasks.md
```

### Source Code (repository root)

```text
host_tools/
├── src/
│   ├── bin/
│   │   ├── probe_protocol.rs
│   │   └── rphsmtool.rs
│   ├── cli/
│   │   ├── args.rs
│   │   ├── commands.rs
│   │   ├── device.rs
│   │   ├── mod.rs
│   │   └── output.rs
│   ├── client.rs
│   ├── lib.rs
│   └── ...
└── Cargo.toml

README.md
.cargo/config.toml
```

**Structure Decision**: Keep the existing `host_tools` split. `rphsmtool`
remains the canonical operator entry point, `probe_protocol` remains the
engineering validation tool, and `host_tools::client` becomes the documented
machine-consumable boundary for integrations. Documentation updates stay in the
repo root and the `specs/009-host-tooling` artifact set.

## Phase 0: Research

- Resolve how `009` should treat the already-implemented `rphsmtool` surface:
  consolidation and support boundary, not greenfield CLI creation.
- Determine the recommended machine-consumable integration surface:
  structured CLI output mode, documented Rust client API, or both.
- Determine best-practice host handling for Linux serial contention,
  permissions, and common system-service interference such as
  `ModemManager`.
- Determine packaging/install expectations that fit this workspace today
  without claiming a distribution story that does not exist yet.

## Phase 1: Design & Contracts

- Define the operator workflow model around canonical commands, prerequisites,
  and explicit engineering-only exceptions.
- Define the host integration surface contract around `host_tools::client`,
  including stability expectations and machine-consumable result semantics.
- Define transport, contention, permission, and packaging behavior contracts
  for supported host environments.
- Update quickstart guidance so it demonstrates canonical operator flows rather
  than probe-only validation sequences.

## Post-Design Constitution Check

- The design keeps trust anchored in device responses rather than host-side
  convenience logic.
- Operator, integration, and engineering surfaces are explicitly separated and
  documented.
- Host-side failure reporting is bounded and actionable without disclosing
  secrets or hidden command surfaces.
- Newly implemented firmware capabilities must be reflected in the supported
  tooling surface or explicitly documented as intentionally unavailable.

## Complexity Tracking

No constitution violations are expected. This feature consolidates and narrows
existing host behavior rather than introducing a broader trust boundary.
