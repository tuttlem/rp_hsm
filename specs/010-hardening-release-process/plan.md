# Implementation Plan: Hardening and Release Process

**Branch**: `010-hardening-release-process` | **Date**: 2026-04-04 | **Spec**: [spec.md](/home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/spec.md)
**Input**: Feature specification from `/specs/010-hardening-release-process/spec.md`

## Summary

Define a release-hardening and approval framework for the RP2350 HSM that turns
security claims into reviewable evidence. The feature adds a documented release
bar, a required hardening matrix for parser/misuse/corruption coverage, a
dependency and build review process, and a bounded release record format that
identifies what was shipped, which checks were run, and which exceptions were
explicitly accepted.

## Technical Context

**Language/Version**: Markdown documentation plus workspace command execution in
the existing Rust/Cargo repository  
**Primary Dependencies**: existing Cargo workspace commands (`cargo test`,
`cargo clippy`, `cargo build`), current firmware/host-tool binaries, `Cargo.lock`,
`README.md`, `SECURITY.md`, and feature specs as the release evidence inputs  
**Storage**: Repo-tracked release-process documentation and release-record
templates; candidate-specific evidence references bounded to documented release
records rather than ad hoc notes  
**Testing**: Review against documented checklist templates, workspace command
execution, live device validation where required by the candidate feature, and
evidence completeness checks during release review  
**Target Platform**: This repository’s Linux-based Cargo development and review
workflow for RP2350 firmware and host tooling  
**Project Type**: Documentation/process feature with supporting repository
artifacts and release-record templates  
**Performance Goals**: Fast, repeatable release review based on bounded evidence
artifacts rather than rediscovery; no runtime performance target introduced by
this feature  
**Constraints**: Must not invent CI/CD infrastructure that does not exist, must
not claim reproducibility or supply integrity beyond evidence the workspace can
actually record, and must fail closed when required evidence is missing,
incomplete, or contradicted  
**Security Boundaries**: Protected assets are release trust, shipped firmware
artifact identity, hardening evidence, and bounded review records. Trust
boundaries are between source tree, local build environment, reviewer-supplied
evidence, and shipped artifact. In-scope attackers include malformed-input and
corruption bugs that escape due to missing verification, accidental or rushed
release approval, and unnoticed dependency or artifact drift. Out of scope are
formal certification claims and perfect supply-chain attestation outside the
recorded workspace process.  
**Scale/Scope**: One repository-level release process covering firmware,
protocol, host tooling, hardening verification, release exceptions, and
artifact approval for each candidate build

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Fail-safe behavior is defined: missing evidence, failed hardening checks,
  incomplete reviews, irreproducible artifacts, and unresolved blockers all
  prevent approval rather than degrade silently into “good enough.”
- Secret-bearing material is bounded: release records may reference test
  outputs and command logs, but they must not retain plaintext proofs, raw
  secret-bearing buffers, or unbounded developer scratch material.
- Externally reachable interfaces are minimized: this feature adds process and
  documentation boundaries, not new firmware or host command surfaces.
- Negative tests and misuse cases are first-class: parser abuse, replay,
  malformed-input, invalid-state, persistence corruption, and denied-operation
  behavior become required release evidence rather than optional extras.
- Release-build and review constraints are central to this feature and must be
  explicitly captured as objective evidence requirements.

## Project Structure

### Documentation (this feature)

```text
specs/010-hardening-release-process/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── release-evidence-schema.md
│   ├── hardening-matrix.md
│   └── exception-and-approval-workflow.md
└── tasks.md
```

### Source Code (repository root)

```text
README.md
SECURITY.md
Cargo.toml
Cargo.lock
.cargo/config.toml

firmware/
host_tools/
protocol/

specs/
└── 00x-... feature artifacts used as release evidence inputs
```

**Structure Decision**: Keep `010` centered on repo-tracked documentation and
release-record contracts. The implementation is expected to update repository
guidance such as `README.md` and `SECURITY.md`, define release-record formats in
the feature contracts, and point release reviewers at the existing Cargo,
firmware, and host-tool validation surfaces rather than inventing a separate
automation stack.

## Phase 0: Research

- Determine how to represent release evidence in a repo that does not yet have
  CI artifacts or external release infrastructure.
- Determine the minimum hardening matrix categories needed to cover parser
  abuse, misuse, replay, invalid-state, persistence corruption, and update
  recovery verification.
- Determine how dependency review should be bounded realistically for the
  existing Cargo workspace.
- Determine how temporary exceptions are recorded without weakening the default
  fail-closed release bar.

## Phase 1: Design & Contracts

- Define the release evidence set, approval record, and exception record data
  model.
- Define a hardening matrix contract that maps required verification classes to
  concrete repo evidence.
- Define the approval and exception workflow, including missing-evidence and
  failed-check behavior.
- Define a quickstart that lets a reviewer assemble and evaluate a candidate
  release using existing workspace commands and live validation outputs.

## Post-Design Constitution Check

- The design fails closed on missing evidence and unresolved hardening gaps.
- The design avoids overstating reproducibility, supply integrity, or build
  guarantees beyond what the repo can actually record.
- The design preserves reviewability by making evidence, exceptions, and
  artifact identity explicit and bounded.
- The design treats denial behavior, corruption handling, and misuse-case
  coverage as required release criteria rather than optional polish.

## Complexity Tracking

No constitution violations are expected. The feature adds explicit release
discipline and evidence formats without expanding the runtime attack surface.
