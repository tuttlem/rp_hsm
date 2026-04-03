# Data Model: Signed Firmware Update

## FirmwarePackageManifest

Represents the trusted metadata for a staged firmware image.

### Fields

- `package_version: u8`
- `image_version_major: u16`
- `image_version_minor: u16`
- `image_version_patch: u16`
- `security_epoch: u16`
- `image_size_bytes: u32`
- `image_digest: [u8; 32]`
- `target_slot: BootSlotId`
- `policy_flags: u16`
- `signature_algorithm: SignatureAlgorithm`
- `signature_bytes: [u8; 64]` in v1 bounded form

### Validation Rules

- `package_version` must match the supported manifest version.
- `image_size_bytes` must fit the inactive slot bounds.
- `target_slot` must refer to the inactive slot, not the active slot.
- `image_digest` must match the fully transferred staged image before
  activation.
- `signature_bytes` must verify against the device’s stored update trust anchor.

## AcceptedFirmwareState

Represents the device’s trusted firmware lineage and boot policy.

### Fields

- `active_slot: BootSlotId`
- `active_version: FirmwareVersion`
- `minimum_accepted_version: FirmwareVersion`
- `trusted_boot_state: TrustedBootState`
- `last_update_result: UpdateResultClass`
- `recovery_required: bool`
- `revision_counter: u32`

### Validation Rules

- `minimum_accepted_version` must never decrease unless an explicit developer
  override feature exists outside production scope.
- `active_version` must be greater than or equal to the minimum accepted
  version.
- `trusted_boot_state` must be one of `active-trusted`, `staged-pending`,
  `staged-validating`, or `recovery-required`.

## FirmwareVersion

Version tuple used for progression and rollback policy.

### Fields

- `security_epoch: u16`
- `major: u16`
- `minor: u16`
- `patch: u16`

### Ordering Rules

1. Compare `security_epoch`
2. Then `major`
3. Then `minor`
4. Then `patch`

### Validation Rules

- Older or equal versions are denied in normal update flow.
- A higher epoch always dominates a lower epoch.

## UpdateAuthorizationContext

Represents the authority and approval conditions for update actions.

### Fields

- `requesting_role: AuthorityRole`
- `session_id: u32`
- `request_counter: u32`
- `policy_revision: u32`
- `approval_ticket_id: Option<u32>`

### Validation Rules

- Must come from an active authenticated administrative session.
- Must satisfy current policy profile and any protected-action approval rules.
- Becomes stale if session, counter, or policy revision changes.

## UpdateTransferState

Tracks an in-progress staged update.

### Fields

- `state: UpdateTransferPhase`
- `manifest: FirmwarePackageManifest`
- `bytes_received: u32`
- `expected_size: u32`
- `staged_digest_state: [u8; 32]` or implementation-specific bounded digest
  accumulator snapshot
- `started_revision: u32`

### State Transitions

- `empty -> manifest-accepted`
- `manifest-accepted -> transferring`
- `transferring -> transferred`
- `transferred -> validating`
- `validating -> activation-pending`
- any state -> `aborted`
- ambiguous restart -> `recovery-required`

### Validation Rules

- Transfer chunks must be contiguous and bounded.
- `bytes_received` must never exceed `expected_size`.
- Activation is forbidden until validation succeeds.

## BootSlotMetadata

Represents the state of one flash image slot.

### Fields

- `slot_id: BootSlotId`
- `slot_state: BootSlotState`
- `stored_version: Option<FirmwareVersion>`
- `stored_digest: Option<[u8; 32]>`
- `bootable: bool`
- `trusted: bool`

### Validation Rules

- Exactly one slot is `active + bootable + trusted` in normal operation.
- Inactive staged slot is never bootable until activation is committed.
- Ambiguous trust or version metadata forces recovery.

## RecoveryState

Represents the safe state entered after failed or ambiguous update processing.

### Fields

- `reason: UpdateRecoveryReason`
- `last_trusted_slot: Option<BootSlotId>`
- `staged_slot: Option<BootSlotId>`
- `authorization_required: bool`

### Validation Rules

- Recovery never treats a partially validated image as trusted.
- Recovery actions must still satisfy authorization and package trust rules.

## Relationships

- `FirmwarePackageManifest` is bound to one `UpdateTransferState`.
- `UpdateTransferState` targets one inactive `BootSlotMetadata`.
- `AcceptedFirmwareState` references the currently active trusted slot and
  version floor.
- `RecoveryState` is derived from `AcceptedFirmwareState` plus slot metadata
  when boot reconciliation fails or validation is incomplete.
