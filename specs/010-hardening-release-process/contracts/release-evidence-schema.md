# Contract: Release Evidence Schema

## Purpose

Define the minimum recorded evidence required before a candidate firmware
artifact can be approved for shipment.

## Required Evidence Sections

1. **Candidate Identity**
   - candidate identifier
   - git commit or equivalent source reference
   - target artifact filename and version
   - artifact hash

2. **Workspace Validation**
   - required software validation commands
   - pass/fail result for each command
   - date/time and operator or reviewer identity

3. **Live Validation**
   - required hardware-validation commands where applicable
   - target device mode or prerequisites
   - pass/fail result for each command

4. **Hardening Matrix**
   - required verification classes
   - evidence references for each class
   - pass/fail/exception state

5. **Dependency and Build Review**
   - dependency delta summary
   - security-relevant impact statement
   - build inputs and artifact provenance summary

6. **Exceptions and Blockers**
   - approved exceptions linked to specific failed or incomplete checks
   - unresolved blockers that prevent approval

7. **Release Decision**
   - approval or rejection
   - reviewer/approver identities or roles
   - date/time

## Approval-State Flow

- `draft`: the record exists but is incomplete
- `review-ready`: all required sections are present and the candidate can be
  judged
- `approved`: the candidate passed all required checks or has explicit approved
  exceptions tied to the exact candidate
- `rejected`: the candidate cannot ship in its current state

## Fail-Closed Rules

- Missing any required section blocks approval.
- Missing artifact identity blocks approval.
- Failed hardening checks block approval unless an explicit approved exception
  covers them.
- Open blockers and incomplete review items block approval.
- `review-ready` is not an implicit approval state; it only means the record is
  complete enough for a bounded decision.
- Dependency review and build review must be recorded against the current
  candidate, including `Cargo.lock` changes, changed manifests, build commands,
  and resulting artifact identity.

## Sensitive Data Rules

- Do not store plaintext proofs, secret-bearing stdin payloads, or raw
  credentials in the release record.
- Record command names, hashes, and bounded outputs only as needed for review.

## Dependency Review Rules

- Review `Cargo.lock` deltas when present.
- Review changed crate manifests and build configuration inputs.
- Call out any changed crate that touches parsing, cryptography, persistence,
  transport, update logic, or build trust.
- Bound the review to what changed in this workspace; do not claim a full
  ecosystem audit if one was not performed.

## Review Outcome

The release record must be sufficient for a reviewer to answer:

- what artifact is under review
- what checks were run
- what failed
- what was accepted temporarily
- why approval or rejection was reached
