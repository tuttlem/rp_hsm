# Quickstart: Signed Firmware Update

## Goal

Validate authorized signed update, version denial, and interrupted-update
recovery without using developer flashing as a substitute for production update
semantics.

## Prerequisites

1. Flash a developer build only to obtain the developer transport:

   ```bash
   cargo firmware-run-developer
   ```

2. Ensure the device is in a known baseline:

   ```bash
   cargo rphsmtool developer-reset --device /dev/ttyACM0
   cargo rphsmtool status --device /dev/ttyACM0
   ```

3. Provision the device and prepare administrator and recovery proofs:

   ```bash
   export RPHSM_PROOF=BOOT
   cargo rphsmtool provision --device /dev/ttyACM0 --proof-env RPHSM_PROOF

   export RPHSM_PROOF=ADMIN
   export RPHSM_RECOVERY=RECVR
   ```

## Scenario 1: Authorized Signed Update

Goal: prove only approved trusted firmware material is accepted.

1. Provision the device to operational state.
2. Apply a signed bounded update package:

   ```bash
   cargo rphsmtool apply-update \
     --device /dev/ttyACM0 \
     --image update.bin \
     --version 1.0.0.1 \
     --role administrator \
     --proof-env RPHSM_PROOF
   ```

3. Read the bounded update status:

   ```bash
   cargo rphsmtool update-status \
     --device /dev/ttyACM0 \
     --role administrator \
     --proof-env RPHSM_PROOF
   ```

Expected outcomes:

- manifest signature is accepted
- version policy allows the candidate
- inactive slot is used for staging
- active trusted firmware remains unchanged until activation succeeds
- post-activation status identifies the new trusted version

## Scenario 2: Rollback and Equal-Version Denial

Goal: prove explicit version progression enforcement.

1. Submit a package with the current trusted version.
2. Submit a package with a lower version or lower security epoch.
3. Read status and audit output.

Expected outcomes:

- equal-version update is denied
- lower-version update is denied
- the active trusted version and rollback floor remain unchanged

## Scenario 3: Interrupted Update Recovery

Goal: prove interrupted update handling never boots untrusted firmware.

1. Apply at least one valid signed update so the device has a non-default active
   trusted version.
2. Inject an ambiguous activation fault and reboot:

   ```bash
   cargo rphsmtool developer-update-fault \
     --device /dev/ttyACM0 \
     --action ambiguous-firmware-activation
   cargo rphsmtool developer-reboot --device /dev/ttyACM0
   ```

3. After reconnect, inspect `status` and `update-status`.
4. Verify the device enters `recovery-required`.
5. Run the authorized trusted recovery action:

   ```bash
   cargo rphsmtool recover-trusted-firmware \
     --device /dev/ttyACM0 \
     --role recovery \
     --proof-env RPHSM_RECOVERY
   ```

6. Confirm the device returns to trusted operation without exposing staged image
   contents.

Expected outcomes:

- partially transferred images are never booted
- ambiguous boot metadata enters recovery rather than guessing
- recovery does not bypass authorization or trust checks

## Observability Expectations

- Status and audit surfaces may show version tuples, slot IDs, transfer phases,
  denial classes, and recovery reasons.
- They must not expose raw image bytes, raw signature bytes, or auth proof
  material.

## Developer-Mode Note

`cargo firmware-run-developer` and picotool flashing are transport conveniences
for lab validation only. They are not evidence that the signed-update policy
path works; the signed-update commands and their audit/policy checks must be
validated separately.
