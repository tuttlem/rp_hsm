# Example: Release Review Walkthrough

## Goal

Demonstrate how a reviewer moves a candidate from `draft` to `review-ready`,
then to either `approved` or `rejected`.

## Candidate A: Missing Artifact Identity

1. Reviewer opens the release evidence record.
2. Candidate hash is blank.
3. Candidate remains `draft`.
4. Reviewer records blocker: "artifact identity incomplete".

Outcome: approval is blocked before any further judgment.

## Candidate B: Complete Evidence

1. Reviewer confirms artifact name, version, hash, commit, and build target.
2. Reviewer checks workspace validation rows and sees every required command
   marked `passed`.
3. Reviewer checks the hardening matrix and sees every class present with an
   evidence reference.
4. Reviewer verifies there are no open blockers.
5. Reviewer marks the record `review-ready`.
6. Reviewer issues final decision:
   - `approved` if all checks pass or are covered by explicit approved
     exceptions
   - `rejected` otherwise

## Fail-Closed Reminder

- Missing sections block progress.
- Missing artifact identity blocks progress.
- A passed happy-path probe does not compensate for omitted hardening coverage.
- Exceptions must be visible in the record, scoped to the candidate, and
  explicitly approved.
