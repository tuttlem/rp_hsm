# Contract: CLI I/O Behavior

## Stdout

- Stdout is reserved for command results only.
- Raw-byte commands emit bytes only, with no banners or progress text.
- Structured commands emit one documented structured representation only.

## Stderr

- Stderr is reserved for diagnostics, usage messages, and non-result warnings.
- Stderr must not contain secret-bearing data, request counters, session proofs,
  wrapped plaintext, or random output.

## Exit Status

- `0`: command completed successfully
- non-zero: command failed due to selection, transport, authorization,
  capability, validation, or device-response errors

## Stdin

- Commands that consume opaque input read from stdin exactly once.
- Empty stdin for a command that requires input is an explicit failure.
- Commands that do not consume stdin must not accidentally block waiting for it.

## Failure Guarantees

- A failed command must not emit partial secret-bearing data to stdout.
- If a device error occurs after a session is established, the CLI may emit
  diagnostics on stderr but must not expose raw protocol fragments unless a
  separate developer-only diagnostic mode is explicitly enabled.
