# Contract: Wrapped Export Policy

## Goal

Define when wrapped export is allowed and what the operator may receive.

## Policy Rules

- Only explicitly exportable key classes may be wrapped-exported.
- Wrapped export MUST remain an authenticated, policy-scoped operation.
- Wrapped export MUST never expose plaintext private-key material.
- Wrapped export MUST preserve enough metadata for controlled reimport and audit
  without leaking secret bytes.

## Required Operator Behavior

- Operators must be able to tell whether a key is exportable before attempting
  wrapped export.
- Export denial reasons must distinguish:
  - non-exportable key
  - wrong lifecycle state
  - wrong role or missing approval
  - unsupported wrapping profile

## Reimport Coherence

- Wrapped export and wrapped import MUST use compatible metadata semantics.
- Reimport MUST preserve algorithm and usage policy.
- Reimported wrapped-export envelopes MAY intentionally return as
  non-exportable if that is the reviewed anti-cloning policy for the profile.
- The product MUST not imply that wrapped export creates a loophole for
  unrestricted key cloning.
