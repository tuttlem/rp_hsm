# Contract: Transport, Packaging, and Support Boundaries

## Purpose

Define supported host-environment expectations and operator guidance for running
the host tooling safely.

## Transport Conditions

Supported tooling must define handling for:

- missing serial device nodes
- insufficient device-node permissions
- busy serial device nodes
- competing host services such as modem-management software
- device re-enumeration after reboot
- incompatible or incomplete firmware surfaces

## Reporting Rules

- Tooling must report these as host or compatibility conditions, not as device
  authorization denials.
- Guidance must be actionable and bounded.
- Diagnostics must not expose secret-bearing payloads.
- Busy-port reporting should mention competing processes or services such as
  `ModemManager`.
- Permission-denied reporting should mention checking the device-node group such
  as `uucp` or `dialout`.
- Missing-device reporting should mention re-enumeration or wrong firmware mode.

## Packaging and Invocation

Until a broader distribution story exists, the supported install/run model is
workspace-based:

- build and run through Cargo in the repo workspace
- identify the canonical operator binary
- identify engineering-only binaries separately

The contract must not imply an installer, package manager release, or OS-native
integration path that does not yet exist.

## Support Boundary

- `rphsmtool`: supported operator surface
- `host_tools::client`: supported machine-consumable integration surface
- `probe_protocol`: engineering validation tool

Each boundary must be documented so users know which surface to choose.
