# Contract: Version and Recovery Policy

## Version Progression

Firmware versions are ordered by:

1. `security_epoch`
2. `major`
3. `minor`
4. `patch`

## Acceptance Rules

- A candidate version lower than `minimum_accepted_version` is denied.
- A candidate version equal to `active_version` is denied in v1.
- A candidate version lower than `active_version` is denied unless an explicit
  future recovery policy says otherwise.
- A candidate version higher than `active_version` may proceed only after
  manifest trust verification and authorization.

## Rollback Policy

- `minimum_accepted_version` advances when a newly activated trusted firmware is
  accepted.
- The device must not claim immutable anti-rollback. The guarantee is based on
  flash-backed accepted-version state and fail-closed restore behavior.
- If version metadata is ambiguous after restart, boot must enter recovery
  rather than guess a lower-trust outcome.

## Slot Activation Policy

- Exactly one slot is trusted and bootable in normal operation.
- The inactive slot may receive staged bytes but is not bootable during
  transfer.
- Activation requires:
  - valid signed manifest
  - version-policy acceptance
  - complete chunk transfer
  - digest match
  - required approval and active authorization

## Interrupted Update Handling

- If interruption happens before finalize, the active trusted slot remains the
  boot target and the staged slot is invalidated or marked incomplete.
- If interruption happens after activation metadata becomes ambiguous, boot
  enters `recovery-required`.
- The device must never boot a partially transferred or unvalidated image.

## Recovery Rules

- Recovery is used to restore trusted operation, not to preserve untrusted
  staged firmware.
- Recovery actions must still be authorized and policy-checked.
- Recovery may restore the last trusted active slot or require a new signed
  package submission, depending on the staged metadata state.
- Recovery output must not expose hidden bypass paths or secret-bearing transfer
  state.
