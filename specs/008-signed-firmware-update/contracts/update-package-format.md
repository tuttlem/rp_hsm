# Contract: Update Package Format

## Overview

The v1 package format is a bounded signed manifest plus externally supplied
image bytes transferred in chunks.

## Manifest Fields

- `manifest_version: u8`
- `image_version.security_epoch: u16`
- `image_version.major: u16`
- `image_version.minor: u16`
- `image_version.patch: u16`
- `image_size_bytes: u32`
- `image_digest_sha256: [u8; 32]`
- `target_slot_hint: u8`
- `policy_flags: u16`
- `signature_algorithm: u8`
- `signature_len: u16`
- `signature_bytes`

## Trust Requirements

- The signed manifest is verified against the device’s stored update trust
  anchor before transfer begins.
- The image digest is verified against the fully transferred staged image before
  activation.
- Trust verification failure denies the update without changing the active
  trusted firmware state.

## Bounds

- Manifest encoding must fit within one bounded privileged command payload.
- Transfer chunk size must fit within the existing framed serial protocol and
  fixed transient buffers.
- Image bytes are never returned in status, audit, or denial responses.

## Redaction Rules

Allowed update observability fields:

- version tuple
- slot ID
- transfer phase
- update result class
- denial class
- recovery reason

Forbidden observability fields:

- raw image bytes
- full manifest signature bytes
- authorization proof material
- intermediate digest workspace or secret-bearing buffers

## Failure Semantics

- malformed manifest encoding: validation denial
- unsupported signature algorithm: command or validation denial
- digest mismatch after transfer: fail closed, staged slot remains untrusted
- ambiguous slot metadata on boot: recovery-required
