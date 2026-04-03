# Data Model: Device State and Provisioning

## Entity: LifecycleState

- Fields:
  - `state_code`: enum value for `factory`, `provisioned`, `operational`,
    `locked`, `recovery`, or `zeroized`
  - `entered_revision`: monotonic revision at which the current state became
    active
  - `allowed_command_profile`: identifier for commands exposed in this state
  - `is_operational`: derived boolean for command gating only
- Validation rules:
  - Exactly one lifecycle state is active at a time
  - `operational` is the only state that enables routine protected functions
  - `zeroized` and `factory` are both non-owned, non-operational states but are
    tracked distinctly for auditability and recovery behavior
- State transitions:
  - `factory -> provisioned`
  - `provisioned -> operational`
  - `operational -> locked`
  - `locked -> operational`
  - `locked -> recovery`
  - `recovery -> provisioned`
  - `recovery -> zeroized`
  - `operational -> zeroized`
  - `provisioned -> zeroized`
  - `zeroized -> provisioned`
  - Any other transition is invalid unless explicitly added in a future spec

## Entity: ProvisioningRecord

- Fields:
  - `record_version`: schema version for flash decoding
  - `lifecycle_state`: current committed `LifecycleState`
  - `pending_transition`: optional `TransitionIntent`
  - `owner_binding`: `OwnerBinding`
  - `recovery_policy`: `RecoveryPolicy`
  - `revision_counter`: monotonic record revision
  - `integrity_tag`: record integrity check value
- Relationships:
  - Owns one `OwnerBinding`
  - May reference one in-flight `TransitionIntent`
  - Uses one `RecoveryPolicy`
- Validation rules:
  - A valid integrity tag is required before the record can be trusted
  - `owner_binding` must be empty in `factory` and `zeroized`
  - `pending_transition` must be cleared on every committed terminal outcome
  - `revision_counter` increases on every successful persistent update

## Entity: OwnerBinding

- Fields:
  - `owner_id`: opaque owner identifier
  - `provisioning_epoch`: owner-establishment revision or timestamp surrogate
  - `authorization_mode`: bootstrap authorization scheme identifier
  - `transfer_allowed`: boolean policy flag
  - `binding_digest`: non-secret digest of bound owner metadata
- Validation rules:
  - Present and complete for `provisioned`, `operational`, `locked`, and
    `recovery`
  - Absent after successful zeroize
  - Must not contain raw secret bootstrap material

## Entity: TransitionIntent

- Fields:
  - `transition_id`: monotonic identifier or nonce-equivalent unique value
  - `source_state`: expected starting `LifecycleState`
  - `target_state`: requested destination `LifecycleState`
  - `command_code`: lifecycle command that initiated the transition
  - `authorization_snapshot`: bounded authorization evidence or digest
  - `created_revision`: record revision when intent was stored
  - `timeout_policy`: whether the intent expires or requires explicit recovery
- Validation rules:
  - Must reference a valid allowed transition pair
  - Must be removed or superseded after reboot reconciliation
  - Must be zeroized from transient memory once committed or rejected

## Entity: RecoveryPolicy

- Fields:
  - `recovery_enabled`: boolean
  - `required_authority`: role required to enter recovery
  - `allowed_exit_targets`: list of permitted post-recovery states
  - `max_attempts`: optional bounded retry count
- Validation rules:
  - `operational` is not a direct recovery exit in this feature
  - Recovery must not broaden privileges beyond the committed owner binding

## Entity: ZeroizeOutcome

- Fields:
  - `result_state`: expected post-zeroize `LifecycleState`
  - `owner_binding_cleared`: boolean
  - `secret_storage_cleared`: boolean
  - `transient_buffers_cleared`: boolean
  - `requires_reprovisioning`: boolean
- Validation rules:
  - All flags must be true before the operation is reported successful
  - `result_state` must be `zeroized`

## Derived Interfaces

- `GetLifecycleStatus`: read-only projection of `LifecycleState`,
  owner-present flag, and recovery-required flag
- `BeginProvisioning`: creates a `TransitionIntent` from `factory` or
  `zeroized` into `provisioned`
- `FinalizeProvisioning`: commits the owner binding and moves
  `provisioned -> operational`
- `LockDevice`: commits `operational -> locked`
- `UnlockDevice`: commits `locked -> operational` after valid authority
- `EnterRecovery`: commits `locked -> recovery` or resolves interrupted
  privileged transitions into `recovery`
- `ExecuteZeroize`: removes `OwnerBinding`, clears secrets, and commits
  `* -> zeroized` where allowed
