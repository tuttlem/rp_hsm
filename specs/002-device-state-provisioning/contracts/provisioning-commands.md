# Contract: Provisioning and Lifecycle Commands

## Command Family Scope

This feature adds lifecycle-management commands to the shared protocol contract.
They remain bounded, state-scoped, and default-deny outside the states listed
below.

## Command Definitions

### `GetLifecycleStatus`

- Purpose: Return the current lifecycle state and high-level ownership flags
- Allowed states: all states
- Required authority: unauthenticated
- Request payload: empty
- Response payload:
  - `state_code`
  - `owner_present`
  - `recovery_required`
  - `pending_transition_present`
- Failure modes:
  - Returns a format error on malformed requests
  - Must not leak owner identifiers, recovery secrets, or bootstrap material

### `BeginProvisioning`

- Purpose: Record a pending owner claim and move `factory` or `zeroized` into a
  bounded pre-operational provisioning flow
- Allowed states: `factory`, `zeroized`
- Required authority: bootstrap owner
- Request payload:
  - bounded owner identifier bytes, max 16 bytes
- Response payload:
  - resulting state
  - transition identifier
  - revision counter
- Failure modes:
  - Invalid payload returns a validation or format error
  - Existing owner binding returns a state denial
  - Persistence failure leaves the device non-operational and signals recovery

### `FinalizeProvisioning`

- Purpose: Commit the owner binding and enable `operational` state
- Allowed states: `provisioned`
- Required authority: bootstrap owner
- Request payload:
  - 4-byte little-endian transition identifier
  - one-byte finalize marker `0xa5`
- Response payload:
  - resulting state
  - committed revision counter
- Failure modes:
  - Mismatched or stale transition identifier returns replay/state denial
  - Integrity check failure returns state denial and leaves operational commands
    disabled

### `LockDevice`

- Purpose: Move `operational -> locked`
- Allowed states: `operational`
- Required authority: administrator
- Request payload: one-byte lock reason code
- Response payload:
  - resulting state
  - lock reason code

### `UnlockDevice`

- Purpose: Move `locked -> operational`
- Allowed states: `locked`
- Required authority: administrator
- Request payload: one-byte unlock marker `0x5a`
- Response payload:
  - resulting state
  - revision counter
- Failure modes:
  - Invalid authorization keeps the device locked
  - Recovery-required condition returns state denial instead of unlocking

### `EnterRecovery`

- Purpose: Move a restricted device into recovery-safe administrative mode
- Allowed states: `locked`
- Required authority: recovery authority
- Request payload: one-byte recovery marker `0xc3`
- Response payload:
  - resulting state
  - recovery-required indicator

### `RecoverToProvisioned`

- Purpose: Exit `recovery` into `provisioned` for a fresh activation path
- Allowed states: `recovery`
- Required authority: recovery authority
- Request payload: one-byte recovery marker `0xc3`
- Response payload:
  - resulting state
  - reactivation transition identifier
  - revision counter

### `ReactivateRecoveredProvisioning`

- Purpose: Move a recovered `provisioned` device back to `operational` through
  a dedicated post-recovery activation path
- Allowed states: `provisioned` after recovery exit
- Required authority: recovery authority or explicitly approved reactivation
  authority
- Request payload:
  - 4-byte little-endian recovery reactivation transition identifier
  - one-byte reactivation confirmation marker
- Response payload:
  - resulting state
  - committed revision counter
- Failure modes:
  - Rejected if the device is merely initially provisioned rather than in the
    post-recovery reactivation path
  - Rejected on stale or mismatched transition identifier

### `ExecuteZeroize`

- Purpose: Destroy owner binding and secret-bearing state and end in
  `zeroized`
- Allowed states: `provisioned`, `operational`, `recovery`
- Required authority: administrator or recovery authority as appropriate
- Request payload:
  - destructive confirmation marker `0xde 0xad`
- Response payload:
  - resulting state
  - zeroize completion flags
- Failure modes:
  - Partial completion is reported as failure and leaves the device in a
    non-operational recovery-safe state
  - Repeated requests after successful zeroize return explicit denial or
    documented idempotent acknowledgement

### `DeveloperResetLifecycle`

- Purpose: Return a lab device to `factory` by clearing lifecycle state,
  ownership state, and pending transitions
- Allowed states: all states
- Required authority: developer-only and `developer-mode` build
- Request payload:
  - developer reset marker `0x44 0x45 0x56`
- Response payload:
  - resulting state
  - owner binding cleared
  - pending transition cleared
  - transient buffers cleared
- Failure modes:
  - Absent from production command catalogs and production builds
  - Invalid marker returns validation error

## Global Validation Rules

- Every lifecycle command declares allowed source states and a single target
  outcome.
- Recovery exit and recovery reactivation are separate commands with separate
  authorization checks.
- No lifecycle command may widen privilege without a committed state change.
- All non-idempotent lifecycle commands must include replay-resistant request
  handling.
- Developer reset is only reachable when `developer-mode` is compiled in.
