# Contract: Host Client Surface

## Purpose

Define the supported machine-consumable boundary for software integrations.

## Supported Boundary

- The host-side reusable client surface is the primary integration boundary.
- Integrations must not depend on scraping human-oriented CLI text formatting as
  their only supported contract.

## Supported Responsibilities

- device discovery and selection
- session establishment and authenticated request transport
- bounded request/response encoding
- explicit device-denial propagation
- bounded host-side error classification for transport and environment failures

## Unsupported Responsibilities

- overriding or shadowing device authorization policy
- inventing host-only success semantics for denied commands
- treating engineering probe output as a stable API

## Result Semantics

- Success results must preserve device-reported state and bounded metadata.
- Device denials must remain distinguishable from host transport or usage
  failures.
- Machine-consumable results must not require parsing ad hoc prose.

## Compatibility Expectations

- The host client must make protocol-version or firmware-surface mismatches
  explicit.
- Conformance guidance must define how supported client behavior is checked
  against the documented device contract.

## Supported Result Shape

- The supported Rust surface is the public `host_tools` library export set.
- Integrations may depend on typed request helpers, typed response structs, and
  machine-readable error classification.
- Integrations should distinguish:
  - device denials
  - host transport conditions
  - malformed or incompatible responses
