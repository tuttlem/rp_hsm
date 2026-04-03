# Implementation Plan: Policy Enforcement

**Branch**: `006-policy-enforcement` | **Date**: 2026-04-03 | **Spec**: [/home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/spec.md](/home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/spec.md)
**Input**: Feature specification from `/specs/006-policy-enforcement/spec.md`

## Summary

Introduce an explicit on-device policy engine for the RP2350 HSM so every
security-relevant command is governed by a documented decision path rather than
scattered conditional logic. The implementation will centralize command policy,
key-usage policy, and approval-gated destructive actions in the shared
`protocol` crate, persist a bounded approval state in firmware, and keep the
result reviewable through stable contracts and denial semantics.

## Technical Context

**Language/Version**: Rust 2024 edition with `no_std` firmware and std-based host tooling  
**Primary Dependencies**: existing `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, flash-backed persistence layer, and current host tools / probes; no new third-party policy engine or dynamic rule runtime  
**Storage**: internal flash-backed persistent policy profile and bounded approval snapshots plus in-RAM policy-decision context and transient approval evaluation buffers  
**Testing**: `cargo test -p rp_hsm --target x86_64-unknown-linux-gnu`, protocol and contract tests for allow/deny matrices, approval-flow tests, malformed and conflicting-policy tests, `cargo clippy`, firmware build validation, and live hardware checks through `cargo probe -- --port ...` in `developer-mode`  
**Target Platform**: RP2350 firmware on `riscv32imac-unknown-none-elf`, with Linux host-side validation over developer-mode USB CDC  
**Project Type**: embedded firmware workspace with shared protocol logic, flash persistence integration, and host-side validation tooling  
**Performance Goals**: deterministic bounded-time policy evaluation on every privileged request, constant decision shape for equivalent inputs, one-pass approval checks without dynamic rule search, and no additional transport round-trips for normal non-destructive commands  
**Constraints**: `no_std`, static allocation only, no host-trusted policy override path, no dynamic scripting or runtime-loaded rules, fail-closed behavior on policy ambiguity or persistence failure, bounded approval state, and no production inclusion of developer-only authority shortcuts  
**Security Boundaries**: protected assets are command authority, key-usage constraints, destructive-action approvals, approval state, and denial semantics; trust boundaries exist between untrusted host requests and device-local policy decisions, between persisted policy/approval state and transient sessions, and between developer-only commands and production policy paths; in-scope attackers include hostile hosts, replayed or reordered privileged requests, stale or partial approvals, role-confusion attempts, and attempts to exploit conflicting state/key rules; out of scope are invasive physical attacks, confidential transport, and third-party policy administration infrastructure  
**Scale/Scope**: one device-local policy domain, one static policy profile in v1, one bounded approval record per protected action class, explicit policy coverage for all current security-relevant command families, and optional dual-control limited to a small destructive-action subset

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Pass. Fail-safe denial is the core feature goal: conflicting rules, missing
  approvals, stale approval state, invalid key usage, and persistence ambiguity
  all resolve to explicit deny outcomes.
- Pass. Secret-bearing elements are limited to transient approval material,
  persisted approval snapshots, and key-usage context derived from managed key
  metadata; all will be bounded and explicitly cleared when no longer needed.
- Pass. No new transport is introduced. The externally reachable surface
  remains the existing command set, but authorization moves into a centralized,
  minimized policy layer.
- Pass. The spec already demands misuse and negative coverage for missing
  policy conditions, approval gaps, and ambiguous state/key combinations, and
  the plan carries those into tests and quickstart validation.
- Pass. Review and release constraints remain explicit: developer-only commands
  must stay outside production policy paths, and the command-to-policy mapping
  must be inspectable in code and contracts.

## Project Structure

### Documentation (this feature)

```text
specs/006-policy-enforcement/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│  ├── approval-workflow.md
│  ├── denial-semantics.md
│  └── policy-command-matrix.md
└── tasks.md
```

### Source Code (repository root)

```text
firmware/
└── src/
    ├── logging.rs
    ├── main.rs
    └── persistence.rs

protocol/
└── src/
    └── protocol/
        ├── codec.rs
        ├── command.rs
        ├── frame.rs
        ├── mod.rs
        ├── parser.rs
        └── state.rs

protocol/tests/
├── contract.rs
├── contract/
├── protocol.rs
└── protocol/

host_tools/
└── src/
    ├── bin/
    │   ├── probe_protocol.rs
    │   └── rphsmtool.rs
    ├── cli/
    └── client.rs
```

**Structure Decision**: Keep policy definition, command-to-policy mapping,
approval evaluation, key-usage checks, and denial semantics in
`/home/michael/src/embedded/rp_hsm/protocol/src/protocol/` so the behavior
stays host-testable and reviewable. Use
`/home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs` only for
persisted policy/approval snapshots and boot-time fail-safe recovery, and use
existing host validation tools only to exercise already-approved device
behavior rather than to decide policy on the host.

## Phase 0: Research

- Choose how policy is represented: static compiled rule tables plus a small
  persisted policy profile, not a dynamic interpreter.
- Choose which destructive actions require stronger approval in v1 and how
  optional dual-control is bounded.
- Choose policy-denial semantics that remain useful for operators but do not
  reveal hidden privilege structure.
- Choose how approval state survives reboot or invalidates on policy, session,
  or lifecycle changes.

## Phase 1: Design & Contracts

- Define policy entities, approval-state entities, and policy-decision inputs
  and outputs.
- Define the full command matrix, including role, device-state, key-usage, and
  approval requirements for each sensitive command family.
- Define the approval workflow for destructive actions and the invalidation
  rules for partial or stale approvals.
- Define bounded denial semantics and quickstart validation for allow/deny,
  destructive approvals, and conflicting policy conditions.
- Update agent context after the design artifacts are written.

## Post-Design Constitution Check

- Pass. The planned design routes every privileged command through one explicit
  policy decision path and denies on ambiguity, missing approval, stale
  approval, or mismatched key/state context.
- Pass. Approval material and persisted approval records are bounded, have
  explicit invalidation rules, and are documented as secret-bearing where they
  could reveal pending destructive authority.
- Pass. No new interface is added; instead the current command set becomes more
  reviewable through a single policy matrix and a bounded approval workflow.
- Pass. Contracts and quickstart validation pair every success flow with deny
  cases for insufficient role, conflicting key usage, missing approval, stale
  approval, and invalid policy references.
- Pass. Developer-only commands remain outside the protected-action approval
  path and must still be absent from production builds and production-visible
  catalogs.

## Complexity Tracking

No constitution violations are expected for this feature.
