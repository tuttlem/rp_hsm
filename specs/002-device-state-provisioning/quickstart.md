# Quickstart: Device State and Provisioning Validation

## 1. Validate Factory-State Reporting

Goal: confirm a fresh or zeroized device reports a non-operational state before
ownership bootstrap.

Expected outcomes:

- `GetLifecycleStatus` reports `factory` or `zeroized`
- no protected operational commands are accepted
- no owner-present flag is exposed as true

## 2. Validate Provisioning Bring-Up

Goal: prove that ownership bootstrap requires both claim and final activation.

Sequence:

1. Send `BeginProvisioning` from `factory`
2. Confirm the device reports `provisioned`
3. Confirm protected operational commands remain denied
4. Send `FinalizeProvisioning`
5. Confirm the device reports `operational`

Expected outcomes:

- operational commands remain unavailable until finalization succeeds
- malformed bootstrap payloads do not change the committed state
- repeated finalization with the same transition identifier is denied safely

## 3. Validate State Enforcement

Goal: ensure only documented transitions succeed.

Sequence:

1. Attempt `UnlockDevice` while in `operational`
2. Attempt `FinalizeProvisioning` while already `operational`
3. Send `LockDevice`
4. Attempt a protected operational command
5. Send `UnlockDevice`

Expected outcomes:

- steps 1 and 2 are denied with explicit state errors
- step 3 enters `locked`
- step 4 is denied without changing state
- step 5 restores `operational` only with valid authority

## 4. Validate Recovery Handling

Goal: ensure recovery is restricted and not a privilege bypass.

Sequence:

1. Enter `locked`
2. Send `EnterRecovery`
3. Attempt a routine protected command
4. Send `RecoverToProvisioned`
5. Confirm operational commands are still denied
6. Send `ReactivateRecoveredProvisioning`
7. Confirm the device returns to `operational`

Expected outcomes:

- recovery does not restore normal operations
- recovery exit returns to `provisioned`, not directly to `operational`
- reactivation requires its own explicit command path

## 5. Validate Zeroize

Goal: prove destructive reset clears ownership and ends in a defined state.

Sequence:

1. Start from `operational` or `recovery`
2. Send `ExecuteZeroize`
3. Reboot the device
4. Query `GetLifecycleStatus`

Expected outcomes:

- owner-present is false after zeroize
- the device reports `zeroized`
- protected commands remain denied until `BeginProvisioning` starts a fresh flow

## 6. Validate Developer Reset

Goal: verify the development-only reset path can recover a lab device while
remaining absent from production images.

Sequence:

1. Flash a `developer-mode` image
2. Move the device into any owned or transitional state
3. Send `DeveloperResetLifecycle`
4. Query `GetLifecycleStatus`
5. Flash a production image and confirm the command is no longer reachable

Expected outcomes:

- the device reports `factory` after developer reset
- owner state and pending transition flags are cleared
- production images do not enumerate or accept the developer reset command

## 7. Validate Interrupted-Transition Safety

Goal: verify power loss or reset cannot silently complete privileged actions.

Sequence:

1. Start a lifecycle command that persists `pending_transition`
2. Reset power before the commit step completes
3. Reboot and query `GetLifecycleStatus`

Expected outcomes:

- the device does not report a guessed successful transition
- the device resolves into `recovery` or another explicitly documented safe
  state
- no protected commands become available without explicit remediation
