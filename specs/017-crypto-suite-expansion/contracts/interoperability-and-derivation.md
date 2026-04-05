# Contract: Interoperability and Derivation Workflows

## Goal

Define the supported sender-side encryption and managed derivation workflows.

## Sender Interoperability Workflow

1. Operator generates a managed recipient key on the HSM.
2. Operator retrieves `public_material` through metadata.
3. An external sender or supported host helper produces an envelope using the
   documented recipient-encryption profile.
4. The HSM accepts that envelope for managed decrypt if the profile, key, role,
   and key usage all match.

## Sender Workflow Requirements

- The sender-side format MUST be documented enough for another system to produce
  a valid envelope without protocol reverse engineering.
- The device MUST deny malformed, truncated, replay-sensitive, tampered, or
  wrong-profile envelopes without exposing plaintext.
- The operator CLI MUST provide a supported path for testing or exercising the
  sender-side workflow.

## Managed Derivation Workflow

1. Operator generates or references a managed key-agreement key.
2. Operator supplies the required peer public material and bounded context.
3. The device derives shared material on-device and expands it through the
   documented derivation profile.
4. The device returns bounded derived output only if policy permits it.

## Derivation Denials

- Wrong role, wrong usage, revoked keys, malformed peer material, and oversized
  output requests MUST fail closed.
- Derivation output MUST be bounded by the documented profile limit.
