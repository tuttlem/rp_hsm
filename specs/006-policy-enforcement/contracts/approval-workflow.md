# Contract: Approval Workflow

## Scope

This workflow applies only to the bounded v1 protected action classes:

- `destructive_admin`
  - `ExecuteZeroize`
- `destructive_key`
  - `DestroyPersistentKey`
- `recovery_transition`
  - `RecoverToProvisioned`
  - `ReactivateRecoveredProvisioning` when paired with a protected recovery path

## Approval Modes

- `single-reviewed-path`
  - one reviewed role is sufficient
  - used when dual-control is disabled for the action class
- `dual-control`
  - two bounded approvals are required before execution
  - used only when the active policy profile enables dual-control for the
    protected action class

## Ticket Lifecycle

### 1. Create Pending Approval

- the initiating approved role requests the protected action
- the device creates a bounded pending approval ticket
- the ticket binds:
  - action class
  - target scope and identifier
  - current policy revision
  - current device revision
  - initiating role

### 2. Confirm Approval

- a second required approval confirms the same target and action class
- the device marks the ticket `confirmed`
- any mismatch in target, role requirements, revision, or expiry denies the
  confirmation

### 3. Execute Protected Action

- the final protected command checks for a matching `confirmed` ticket
- if present and current, the command executes
- on success, the ticket becomes `consumed`

## Invalidation Rules

A ticket becomes invalid immediately if any of these occur before execution:

- approval timeout or expiry
- policy revision change
- device revision change affecting the bound target
- lifecycle transition that invalidates the target state
- reboot recovery ambiguity
- explicit developer reset or zeroize
- successful use by another command

## Fail-Safe Behavior

- missing ticket -> deny
- stale ticket -> deny and invalidate
- conflicting ticket binding -> deny
- multiple candidate tickets -> deny
- persistence ambiguity for approval storage -> deny all protected actions until
  a reviewed recovery path resolves the state

## Auditability Notes

- the ticket structure and protected action mapping must be reviewable in code
  and contracts
- operator-visible feedback may indicate that approval is missing or stale, but
  must not disclose hidden role structure or secret approval material
