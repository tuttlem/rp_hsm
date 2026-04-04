# Research: Hardening and Release Process

## Decision: Use repo-tracked release records and evidence templates rather than inventing CI-only artifacts

**Rationale**: This repository currently has no CI pipeline or external release
system to anchor the process. A realistic release process must be executable by
reviewers using the existing Cargo workspace, feature specs, probe tooling, and
documented command outputs. Repo-tracked templates keep the process reviewable
without pretending that automation already exists.

**Alternatives considered**:

- CI-generated release bundles: rejected because no such infrastructure exists
  in the repo today.
- Informal release notes only: rejected because they are too weak to satisfy
  the evidence and fail-closed requirements in the spec.

## Decision: Define the hardening matrix around verification classes, not individual bugs

**Rationale**: The release bar needs to remain stable as features evolve. A
matrix organized by classes such as parser abuse, authorization misuse, replay,
invalid-state transitions, persistence corruption, audit recovery, and update
recovery creates a repeatable review surface while still allowing each release
to point to concrete tests and hardware runs.

**Alternatives considered**:

- Track only feature-by-feature happy-path completion: rejected because the spec
  explicitly requires negative and abuse-case evidence.
- Track only ad hoc known issue lists: rejected because that turns hardening
  into a reactive process instead of a release criterion.

## Decision: Use existing workspace commands plus feature-specific live validation as the reproducibility baseline

**Rationale**: The workspace already has a repeatable command surface for
software validation and on-device checks. The release process can require the
exact commands, tool inputs, and resulting artifact identifiers to be recorded.
That is strong enough to support review without making false claims about
bit-for-bit global reproducibility or external supply-chain attestation.

**Alternatives considered**:

- Claim strong reproducible-build guarantees now: rejected because the repo does
  not currently demonstrate or enforce them end to end.
- Treat a successful `cargo build` as sufficient evidence: rejected because the
  spec requires explicit artifact identification and dependency/build review.

## Decision: Dependency review is a bounded change review over `Cargo.lock`, direct dependency deltas, and security-relevant impact

**Rationale**: A realistic dependency review for this repo should focus on what
changed, why it changed, and whether the changed crates affect security
boundaries such as parsing, cryptography, persistence, transport, or build
trust. Reviewing `Cargo.lock`, changed crate manifests, and affected trust
boundaries gives a repeatable process without pretending that a full supply
chain audit is happening for every release.

**Alternatives considered**:

- No dependency review when functionality looks unchanged: rejected because the
  spec explicitly calls out supply and build risk.
- Full ecosystem audit every release: rejected as unrealistic for the current
  project stage and likely to produce paper compliance instead of useful review.

## Decision: Release evidence should reference exact workspace commands and bounded outputs instead of attaching raw logs by default

**Rationale**: This repo already uses a stable set of Cargo, probe, and
`rphsmtool` commands. Recording the exact command, result, candidate identity,
and a bounded summary is enough for review while avoiding accidental retention
of secrets, excessive serial logs, or irrelevant build noise.

**Alternatives considered**:

- Attach every raw log file to the release record: rejected because it increases
  secret-handling risk and makes review noisy.
- Record only pass/fail with no command details: rejected because it weakens
  traceability and reviewer confidence.

## Decision: Exceptions are allowed only as explicit signed-off deviations tied to a specific candidate artifact

**Rationale**: The spec allows temporary exceptions, but only if they are
 documented, scoped, and approved. Tying an exception to a specific candidate
 artifact, evidence gap, rationale, mitigation, and expiry/revisit expectation
 prevents exceptions from becoming permanent undocumented drift.

**Alternatives considered**:

- Blanket “known issues” approval: rejected because it weakens the fail-closed
  release bar.
- No exceptions ever: rejected because the spec explicitly assumes that some
  issues may be carried temporarily through a controlled process.
