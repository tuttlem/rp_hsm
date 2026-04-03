# Contract: Firmware Update Commands

## Scope

These commands define the v1 signed firmware update control plane. They are
administrative commands and are never public.

## Command: `GetFirmwareUpdateStatus`

- **Purpose**: Return bounded non-secret update and recovery status.
- **Authorization**: `administrator` or `recovery`
- **Allowed device states**: `operational`, `locked`, `recovery`, `zeroized`
- **Request payload**: authorized header only
- **Response payload**:
  - `active_slot: u8`
  - `active_version: FirmwareVersion`
  - `minimum_accepted_version: FirmwareVersion`
  - `transfer_phase: u8`
  - `staged_slot_state: u8`
  - `recovery_required: u8`
  - `last_update_result: u8`

## Command: `BeginFirmwareUpdate`

- **Purpose**: Submit a signed manifest and allocate a staged transfer session.
- **Authorization**: `administrator`
- **Allowed device states**: `operational`
- **Protected action**: may require approval when policy marks firmware update
  as dual-control sensitive
- **Request payload**:
  - authorized header
  - `manifest_version: u8`
  - bounded encoded manifest fields
  - `signature_len: u16`
  - `signature_bytes`
- **Success response**:
  - `target_slot: u8`
  - `update_session_id: u32`
  - `expected_size: u32`
  - `policy_revision: u32`
- **Failure semantics**:
  - unauthorized or stale approval: bounded denial
  - invalid signature: fail closed
  - equal/older version: deny with version/rollback class
  - active conflicting workflow: deny with state class

## Command: `TransferFirmwareChunk`

- **Purpose**: Write one bounded chunk into the inactive slot.
- **Authorization**: `administrator`
- **Allowed device states**: `operational`
- **Request payload**:
  - authorized header
  - `update_session_id: u32`
  - `chunk_offset: u32`
  - `chunk_len: u16`
  - `chunk_bytes`
- **Success response**:
  - `bytes_received: u32`
  - `remaining_bytes: u32`
- **Failure semantics**:
  - out-of-order or oversized chunk: deny, do not partially advance
  - stale session or lost authority: deny and invalidate staged workflow if
    policy requires

## Command: `FinalizeFirmwareUpdate`

- **Purpose**: Complete transfer verification and mark the staged slot pending
  activation.
- **Authorization**: `administrator`
- **Allowed device states**: `operational`
- **Protected action**: same policy class as begin/activate
- **Request payload**:
  - authorized header
  - `update_session_id: u32`
  - confirmation marker
- **Success response**:
  - `staged_slot: u8`
  - `validated_version: FirmwareVersion`
  - `activation_pending: u8`
- **Failure semantics**:
  - incomplete transfer, digest mismatch, or stale approval/session all deny and
    leave the active trusted slot unchanged

## Command: `ActivateFirmwareUpdate`

- **Purpose**: Commit the validated staged image as the next boot target.
- **Authorization**: `administrator`
- **Allowed device states**: `operational`
- **Protected action**: approval-gated in policy profile
- **Request payload**:
  - authorized header
  - `update_session_id: u32`
  - activation marker
- **Success response**:
  - `next_boot_slot: u8`
  - `next_version: FirmwareVersion`
  - `reboot_required: u8`
- **Failure semantics**:
  - never marks an image bootable unless manifest, digest, and version checks
    already succeeded

## Command: `AbortFirmwareUpdate`

- **Purpose**: Cancel the in-progress staged update and invalidate incomplete
  transfer state.
- **Authorization**: `administrator`
- **Allowed device states**: `operational`, `recovery`
- **Request payload**:
  - authorized header
  - `update_session_id: u32`
- **Success response**:
  - `transfer_state_cleared: u8`
  - `staged_slot_invalidated: u8`

## Command: `RecoverTrustedFirmware`

- **Purpose**: Explicitly recover into the last trusted active firmware state
  after interrupted or ambiguous update processing.
- **Authorization**: `recovery`
- **Allowed device states**: `recovery`
- **Protected action**: may require approval per policy
- **Success response**:
  - `restored_slot: u8`
  - `restored_version: FirmwareVersion`
  - `recovery_required: u8=0`

## Command Rules

- Update commands must be hidden from public catalogs.
- Update commands must never expose raw firmware contents in responses.
- Status and audit output may identify slot IDs, versions, result classes, and
  denial classes, but not secret-bearing authorization material.
