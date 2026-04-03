# Contract: Device Discovery And Selection

## Discovery Rules

- Discovery must scan only host-visible transports that the RP HSM project
  officially supports.
- Discovery must classify candidates as compatible, incompatible, or unknown.
- Only compatible candidates may be returned by `rphsmtool find` as selectable
  targets.
- Discovery output must include enough information for an operator to select a
  device deterministically.

## Selection Rules

- `--device <selector>` must target one specific compatible device or fail.
- If `--device` is omitted:
  - zero compatible devices -> fail closed
  - one compatible device -> select it
  - more than one compatible device -> fail closed and instruct the user to
    specify `--device`

## Failure Behavior

- The tool must not silently fall back to an arbitrary device.
- The tool must not contact more than one candidate for a stateful command once
  selection is resolved.
- If the selected device disappears before or during an operation, the command
  fails with a non-zero exit status and no fabricated result.

## Security Notes

- Discovery metadata must never be treated as proof of stronger device identity
  than the firmware actually provides.
- Developer-only surfaces must be labeled as such when they are distinguishable.
