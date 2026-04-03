# Quickstart: Policy Enforcement Validation

## 1. Validate Command Matrix Enforcement

Goal: prove role, session, and lifecycle rules are enforced by explicit policy.

Sequence:

1. Boot a developer-mode device into a clean known state
2. Authenticate as each reviewed role in turn
3. Attempt representative commands from allowed and disallowed roles
4. Compare the results against the policy command matrix

Expected outcomes:

- commands allowed by role and state succeed
- commands denied by role, state, or key policy fail without partial execution
- deny behavior is stable across repeated equivalent requests

## 2. Validate Key Usage Policy

Goal: prove managed-key actions obey key policy rather than only session role.

Sequence:

1. Place the device into an operational state with at least one managed key
2. Attempt `SignDetached` with a compatible signing key
3. Attempt the same command with a key whose usage or lifecycle is incompatible
4. Attempt `DestroyPersistentKey` on keys in valid and invalid lifecycle states

Expected outcomes:

- compatible key use succeeds
- incompatible key use is denied because of policy
- destructive key actions require the documented approval path when dual-control
  is enabled in the persisted policy profile

## 3. Validate Protected Action Approval

Goal: prove destructive operations do not execute unless their approval path is
complete.

Note: the current external command surface does not include a runtime switch for
enabling dual-control on-device. The approval-ticket workflow is therefore
validated in protocol tests with explicit policy-profile setup, while hardware
quickstart runs continue to validate the bounded denial classes and the single-
reviewed-path default profile.

Sequence:

1. Request a protected action such as `ExecuteZeroize` or
   `DestroyPersistentKey`
2. Attempt the same action without the required approval completion
3. Complete the documented approval path
4. Reattempt the action

Expected outcomes:

- incomplete approval denies execution
- completed approval allows the action
- approval artifacts are consumed or invalidated after use

## 4. Validate Approval Staleness And Invalidation

Goal: prove partial approvals do not survive unsafe context changes.

Sequence:

1. Create a pending approval for a protected action
2. Change one invalidating input such as policy revision, lifecycle state, or
   device revision
3. Retry the protected action

Expected outcomes:

- the stale approval is rejected
- the device reports a bounded stale-approval failure
- no partial destructive action executes

## 5. Validate Reviewability

Goal: prove security reviewers can trace every sensitive command to an explicit
policy rule.

Sequence:

1. Inspect `policy-command-matrix.md`
2. Inspect `approval-workflow.md`
3. Inspect `denial-semantics.md`
4. Cross-check representative commands from each sensitive family

Expected outcomes:

- every sensitive command maps to one documented rule path
- destructive commands identify their approval class explicitly
- denial outcomes can be understood without reading scattered implementation
  branches
