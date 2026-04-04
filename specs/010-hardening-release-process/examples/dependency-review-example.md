# Example: Dependency Review

## Candidate

- `candidate_id`: `rc-010-dependency-review`
- `artifact_version`: `0.10.0-rc3`

## Inputs Reviewed

- `Cargo.lock`: changed
- changed manifests:
  - `host_tools/Cargo.toml`
  - `protocol/Cargo.toml`

## Delta Summary

- Added one host-only formatting dependency
- No new firmware-side cryptography or parser dependencies
- No change to target triple or linker configuration

## Security-Relevant Impact

- Host-only dependency does not execute on the RP2350 target
- Shared protocol dependency change touches parsing and therefore requires
  parser-abuse evidence to stay in scope

## Review Result

- acceptable with recorded parser evidence and no unresolved blockers
