# Quickstart: Hardening and Release Readiness Review

## Goal

Evaluate a candidate release using objective evidence from the existing
workspace instead of informal confidence.

## Prerequisites

1. Identify the candidate artifact and source revision.
2. Ensure the repository is at the candidate commit.
3. If live validation is required, ensure a developer-mode device is available
   and serial access is configured.

## Step 1: Record Candidate Identity

Fill the candidate-identity section of
`release-evidence-template.md`. Capture:

- candidate identifier
- git commit
- artifact filename
- artifact hash

## Step 2: Run Required Workspace Validation

Run the required software validation commands for the candidate feature set, for
example:

```bash
cargo test -p rp_hsm --target x86_64-unknown-linux-gnu
cargo test -p host_tools
cargo clippy -p rp_hsm --target x86_64-unknown-linux-gnu --tests -- -W clippy::pedantic
cargo clippy -p host_tools -- -W clippy::pedantic
cargo build -p firmware --target riscv32imac-unknown-none-elf --features developer-mode
```

Record pass/fail outcomes in the release evidence set.
Use bounded summaries and evidence references instead of pasting entire raw
logs unless a reviewer explicitly needs the raw capture.

## Step 3: Confirm Hardening Coverage

For the candidate, confirm the evidence set covers:

- parser and malformed-input abuse cases
- authorization and misuse denials
- invalid-state handling
- persistence corruption and recovery behavior
- update recovery behavior if firmware update logic changed

If any required class is missing, the candidate is blocked.
Use `hardening-matrix-template.md` to make each class visible during review.

## Step 4: Review Dependency and Build Changes

Review:

- `Cargo.lock` changes
- changed crate manifests
- security-relevant dependency impact
- the exact commands used to build the artifact

Record what changed and why it is acceptable.
If a dependency, manifest, or build input touches parsing, cryptography,
persistence, transport, audit, or update trust, call that out explicitly.

## Step 5: Run Live Validation Where Required

If the candidate touches hardware-facing security behavior, run the relevant
live validation commands, for example:

```bash
cargo probe -- --port /dev/ttyACM0
cargo rphsmtool status --device /dev/ttyACM0
```

Record the command and result. Do not store secret-bearing material in the
final release record.

## Step 6: Resolve Exceptions or Reject the Candidate

- If all required checks pass, mark the evidence set `review-ready`.
- If a check fails or is incomplete, either:
  - reject the candidate, or
  - create an explicit exception with rationale, mitigation, and approver

Use `release-exception-template.md` for any temporary deviation. Do not waive
artifact identity, review traceability, or dependency/build review.

## Step 7: Approve or Reject

Approve only when:

- artifact identity is complete
- all required evidence is present
- all hardening classes are `passed` or covered by approved exceptions
- unresolved blockers are empty

Reject otherwise.

## Quick Validation Against the Templates

Before closing the review, confirm:

- `release-evidence-template.md` can hold the candidate identity, validation,
  hardening, dependency, and build evidence you collected
- `hardening-matrix-template.md` shows every required class for the candidate
- `approved-artifact-template.md` can be filled without inventing missing data
- any carried deviation is captured in `release-exception-template.md`
