# Release Evidence Template

## Release Record Header

- `candidate_id`:
- `approval_state`: `draft`
- `candidate_scope`:
- `prepared_by`:
- `prepared_on`:

## Candidate Identity

- `artifact_name`:
- `artifact_version`:
- `artifact_path`:
- `artifact_hash`:
- `source_commit`:
- `source_ref`:
- `target_triple`:
- `feature_flags`:

## Workspace Validation

Record every required software validation command for the candidate scope.
Approval is blocked if any required command is omitted, not run, or failed.

| Command | Scope | Result | Evidence Reference | Reviewer Notes |
| --- | --- | --- | --- | --- |
| `cargo test -p rp_hsm --target x86_64-unknown-linux-gnu` | | `not-run` | | |
| `cargo test -p host_tools` | | `not-run` | | |
| `cargo clippy -p rp_hsm --target x86_64-unknown-linux-gnu --tests -- -W clippy::pedantic` | | `not-run` | | |
| `cargo clippy -p host_tools -- -W clippy::pedantic` | | `not-run` | | |
| `cargo build -p firmware --target riscv32imac-unknown-none-elf --features developer-mode` | | `not-run` | | |

## Live Validation

Use this section only when the candidate touches hardware-facing behavior,
security state transitions, persistence, audit, firmware update, or host/device
integration boundaries. Record the exact command and a bounded result summary.

| Command | Preconditions | Result | Evidence Reference | Reviewer Notes |
| --- | --- | --- | --- | --- |
| `cargo probe -- --port /dev/ttyACM0` | developer-mode image flashed | `not-run` | | |
| Feature-specific `cargo rphsmtool ...` sequence | serial access configured | `not-run` | | |

## Hardening Matrix Summary

Every required verification class must be visible during approval review. A
passing happy-path command does not compensate for a missing hardening class.

| Check ID | Category | Candidate Scope | Status | Evidence Reference | Exception ID | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `HC-PARSER-01` | parser abuse and malformed input | | `not-run` | | | |
| `HC-MISUSE-01` | authorization and misuse | | `not-run` | | | |
| `HC-STATE-01` | invalid-state handling | | `not-run` | | | |
| `HC-PERSIST-01` | persistence corruption and recovery | | `not-run` | | | |
| `HC-UPDATE-01` | firmware update recovery | | `not-run` | | | |
| `HC-SUPPLY-01` | supply and build review | | `not-run` | | | |

## Dependency Review

- `cargo_lock_changed`:
- `changed_manifests`:
- `changed_crates`:
- `security_relevant_boundaries_touched`:
- `review_summary`:
- `acceptable_risk_basis`:

## Build Review

- `build_host`:
- `rustc_version`:
- `cargo_version`:
- `build_commands`:
- `runner_or_flasher_used`:
- `artifact_provenance_notes`:

## Exceptions and Blockers

### Linked Exceptions

- `exception_id`:
- `affected_checks`:
- `status`:
- `mitigation`:

### Open Blockers

- `blocker_id`:
- `description`:
- `owner`:
- `resolution_needed_before_approval`:

## Review Outcome

- `review_ready_check`:
- `release_decision`: `pending`
- `reviewers`:
- `decision_timestamp`:
- `decision_basis_summary`:

## Fail-Closed Rules

- This record must stay `draft` until candidate identity, validation evidence,
  hardening coverage, dependency review, and build review are all present.
- `review-ready` means the record is complete enough to decide, not that it is
  already approved.
- `approved` is allowed only when all required checks are `passed` or covered
  by explicit approved exceptions tied to this candidate.
- `rejected` is required when artifact identity is incomplete, evidence is
  missing, blockers remain open, or a non-waivable rule would otherwise be
  waived.
