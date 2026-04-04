# Contract: Exception and Approval Workflow

## Purpose

Define how reviewers handle incomplete evidence, failed checks, and temporary
exceptions without weakening the default release bar.

## Default Rule

The default release rule is fail-closed:

- missing evidence blocks approval
- failed required checks block approval
- incomplete review blocks approval

## Exception Workflow

1. A reviewer identifies a failed or incomplete required check.
2. The candidate remains blocked unless an explicit exception is proposed.
3. The exception must record:
   - affected check(s)
   - candidate artifact identity
   - rationale
   - security impact
   - mitigation
   - approver
   - revisit or expiry trigger
4. The release record must show the approved exception clearly.

## Non-Waivable Expectations

Exceptions must not waive:

- candidate artifact identity
- release decision traceability
- dependency/build review entirely
- visibility of unresolved security impact
- reviewer visibility into the exact affected checks
- the requirement that blockers remain visible until resolved or explicitly
  rejected

## Approval Outcome

- **Approved**: all required checks passed or are covered by approved exceptions
- **Rejected**: missing evidence, failed checks without approved exceptions, or
  unresolved blockers remain

## Traceability Requirements

- Every approval outcome must name the candidate artifact identity.
- Every carried exception must be listed in both the release evidence set and
  the approved artifact record.
- Every rejection must leave enough detail for a later reviewer to understand
  what blocked shipment.

## Sensitive Material Handling

- Temporary validation files and logs must be retained only as long as needed
  for review.
- Secret-bearing or unnecessary raw captures must be destroyed or omitted from
  the final release record.
