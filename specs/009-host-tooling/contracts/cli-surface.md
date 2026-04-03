# Contract: Canonical CLI Surface

## Purpose

Define the supported operator-facing behavior of `rphsmtool` after host-tooling
consolidation.

## Canonical Operator Tool

- `rphsmtool` is the canonical operator-facing CLI.
- `probe_protocol` is an engineering validation tool, not the default operator
  interface.

## Supported Behavior

- Operators can complete supported workflows without constructing raw protocol
  frames.
- Stdout remains result-oriented.
- Stderr remains diagnostic-oriented.
- Denials from the device are presented accurately and are not rewritten into
  false host-side success states.

## Workflow Coverage Rules

- Provisioning, administration, diagnostics, audit review, recovery, and
  firmware update workflows must either:
  - be supported through `rphsmtool`, or
  - be explicitly documented as engineering-only.

## Error Reporting Rules

- Busy serial ports, missing permissions, missing devices, and incompatible
  firmware must be reported as host-side access or compatibility issues.
- Device policy denials, state denials, and authorization denials must remain
  identifiable as device-originated outcomes.
- The CLI must not imply that a host-side retry or fallback bypasses device
  policy.

## Development and Engineering Separation

- Developer-only commands may be present in `rphsmtool`, but they must be
  labeled as development-only.
- Engineering validation sequences belong to `probe_protocol`, even when they
  reuse the same transport and command surfaces.
- Default help must remain grouped by user intent so operator workflows are
  visible without reading engineering-oriented command inventories.

## Completion Rule

- When a new firmware capability becomes user-relevant, the CLI surface must
  record one explicit decision:
  - exposed through `rphsmtool`
  - available only through the host integration surface
  - engineering-only
  - intentionally unavailable

Undocumented limbo states are not allowed.

## Capability Exposure Checklist

For each newly implemented firmware capability:

1. decide whether it is operator-facing, client-only, engineering-only, or
   intentionally unavailable
2. add or update `rphsmtool` help and examples if it is operator-facing
3. update `host_tools::client` exports if it is part of the supported
   machine-consumable surface
4. document why it remains engineering-only or unavailable if it is not exposed
