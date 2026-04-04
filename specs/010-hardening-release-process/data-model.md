# Data Model: Hardening and Release Process

## Entity: Release Evidence Set

**Purpose**: The complete recorded basis for deciding whether a candidate
artifact can ship.

**Fields**:

- `candidate_id`: human-readable identifier for the release candidate
- `artifact_identity`: firmware artifact name, version, and cryptographic hash
- `source_reference`: git commit, branch/tag, and relevant feature set
- `workspace_validation`: recorded software validation commands and outcomes
- `live_validation`: recorded hardware validation commands and outcomes
- `hardening_matrix_status`: pass/fail/exception status for each required
  verification class
- `dependency_review_reference`: link or section identifying dependency delta
  review
- `build_review_reference`: link or section identifying build inputs and outputs
- `open_blockers`: unresolved issues that prevent approval
- `exceptions`: zero or more linked `Release Exception` records
- `approval_state`: `draft`, `review-ready`, `approved`, or `rejected`

**Validation rules**:

- Must identify exactly one candidate artifact.
- Must not be `approved` if any required evidence item is missing.
- Must not be `approved` if any required hardening class is failed and not
  covered by an approved exception.
- Must not include secret-bearing proof values or transient developer material.

## Entity: Hardening Check

**Purpose**: One required verification activity in the release bar.

**Fields**:

- `check_id`: stable identifier
- `category`: parser, misuse, replay, invalid-state, persistence corruption,
  audit recovery, firmware update recovery, dependency review, or build review
- `description`: what must be verified
- `required_evidence`: the specific artifact or command output that demonstrates
  completion
- `status`: `not-run`, `passed`, `failed`, or `exception`
- `candidate_scope`: features or trust boundaries affected by this check
- `notes`: bounded reviewer notes

**Validation rules**:

- Every release candidate must evaluate every required check.
- `exception` status must reference a `Release Exception`.
- `passed` status must cite evidence that is specific to the candidate or still
  valid for the candidate scope.

## Entity: Release Exception

**Purpose**: A temporary, approved deviation from the default release bar.

**Fields**:

- `exception_id`: stable identifier
- `candidate_id`: candidate artifact to which the exception applies
- `affected_check_ids`: one or more `Hardening Check` identifiers
- `issue_summary`: concise description of the carried issue
- `security_impact`: bounded explanation of the risk
- `mitigation`: current mitigation or operator caveat
- `approval_owner`: reviewer or approver responsible
- `expiry_or_revisit_trigger`: when the exception must be re-evaluated
- `status`: `proposed`, `approved`, `rejected`, or `expired`

**Validation rules**:

- Must not exist without a matching candidate artifact.
- Must not approve a release silently; it must be visible in the evidence set.
- Must not waive artifact identity, build review, or dependency review
  entirely.

## Entity: Approved Artifact Record

**Purpose**: The final release record that identifies what was shipped and why.

**Fields**:

- `artifact_identity`: version, filename, and hash
- `approval_timestamp`: when the release was approved
- `approval_basis`: reference to the `Release Evidence Set`
- `release_decision`: `approved` or `rejected`
- `approver_set`: the reviewer identities or roles that approved it
- `carried_exceptions`: any approved exceptions attached to this artifact

**Validation rules**:

- Must reference exactly one approved evidence set.
- Must be sufficient for a reviewer to identify what artifact was approved and
  which exceptions remain open.

## Relationships

- One `Release Evidence Set` contains many `Hardening Check` evaluations.
- One `Release Evidence Set` may contain zero or more `Release Exception`
  records.
- One `Approved Artifact Record` references exactly one `Release Evidence Set`.
- One `Release Exception` may satisfy or waive one or more `Hardening Check`
  records for exactly one candidate artifact.

## State Transitions

### Release Evidence Set

- `draft` -> `review-ready` when all required evidence is present
- `review-ready` -> `approved` when all required checks pass or are explicitly
  exception-approved
- `review-ready` -> `rejected` when blockers, failed checks, or missing evidence
  remain

### Approved Artifact Record

- created only after one `Release Evidence Set` reaches `approved`
- must carry forward any approved exceptions that remain open for the artifact
- must not exist for a rejected candidate

### Release Exception

- `proposed` -> `approved` when explicitly accepted
- `proposed` -> `rejected` when the risk is not accepted
- `approved` -> `expired` when its revisit trigger is reached or the candidate
  changes
