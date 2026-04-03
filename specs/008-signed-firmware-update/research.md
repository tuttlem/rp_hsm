# Research: Signed Firmware Update

## Decision 1: Use a bounded signed manifest plus chunked image transfer

**Decision**: Represent an update package as a signed manifest containing image
metadata, version fields, size, digest, target slot, and policy flags, followed
by chunked image transfer into an inactive slot. Firmware verifies the manifest
signature before accepting transfer and verifies the staged image digest before
activation.

**Rationale**: This separates trust-bearing metadata from bulk transfer data and
fits the existing bounded command model. It also allows the firmware to reject
untrusted or rollback-violating updates before committing to boot activation.

**Alternatives considered**:

- Raw unsigned image push with post-write host trust: rejected because host-side
  trust alone does not protect the device boundary.
- Monolithic image upload in one request: rejected because it does not fit the
  bounded serial protocol model.
- Direct bootloader replacement now: rejected because the repo’s current
  feature scope is device policy, persistence, and operator tooling, not a
  bespoke second-stage bootloader rewrite.

## Decision 2: Store accepted-version floor and slot metadata in flash-backed update state

**Decision**: Persist an `AcceptedFirmwareState` that records the currently
trusted active version, minimum allowed rollback floor, active slot, staged-slot
state, and activation/recovery markers.

**Rationale**: The constitution requires honest anti-rollback claims. A stored
 version floor plus explicit slot metadata is reviewable and enforceable in
 firmware without claiming immutable hardware rollback protection.

**Alternatives considered**:

- Trust only the active image version at boot: rejected because interrupted or
  stale staged images become ambiguous.
- Claim hardware-enforced anti-rollback: rejected because the RP2350 platform
  does not justify that claim by itself in this project.

## Decision 3: Use two bootable image states in v1: active trusted and inactive staged

**Decision**: Model one active trusted slot and one inactive staged slot. Only
the active slot is bootable by default. Activation requires successful manifest
verification, complete image transfer, digest verification, policy approval,
and an explicit activation marker.

**Rationale**: This is the smallest slot model that supports safe staging,
interruption handling, and recoverable rollback denial semantics.

**Alternatives considered**:

- In-place overwrite of active firmware: rejected because interrupted writes can
  brick the device or erase the last known good image.
- More than two slots: rejected for now because it increases flash-management
  complexity without helping the core trust model.

## Decision 4: Treat firmware update as an approval-gated administrative action

**Decision**: Require authenticated administrator authority to initiate update
transfer, and apply existing policy/approval controls to activation and
recovery-sensitive steps. Dual control must be able to gate activation when the
policy profile requires it.

**Rationale**: Firmware update is a system-wide trust boundary and fits the same
administrative risk category as zeroize and destructive lifecycle changes.

**Alternatives considered**:

- Recovery-role-only updates: rejected because routine update should be an admin
  maintenance operation, while recovery remains for failed-update remediation.
- Public or unauthenticated update submission: rejected because it violates the
  product’s authorization model.

## Decision 5: Interrupted or ambiguous update state must boot only the last trusted active image or enter recovery

**Decision**: On boot, firmware reconciles update metadata. If the active slot
is still trusted and staged state is merely incomplete, continue booting the
active image and mark staged data invalid. If slot metadata is ambiguous or the
boot target cannot be trusted, enter a defined recovery-required state instead
of guessing.

**Rationale**: This matches the constitution’s fail-safe requirement and the
feature spec’s recovery expectations.

**Alternatives considered**:

- Auto-continue into the newest partially written image: rejected as unsafe.
- Silent metadata repair without explicit degraded state: rejected because it
  hides trust ambiguity.

## Decision 6: Keep developer flashing explicitly separate from production signed-update behavior

**Decision**: `cargo firmware-run-developer` and picotool flashing remain
developer-mode only and are not part of the signed-update security claim.
Production update validation must go through the signed package commands and
their policy/audit path.

**Rationale**: The spec explicitly distinguishes production update from
development flashing. Keeping them separate avoids misleading validation.

**Alternatives considered**:

- Reusing developer flashing as the production update path: rejected because it
  bypasses the intended authorization, manifest verification, version policy,
  and audit rules.
