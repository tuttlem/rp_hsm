# Contract: rphsmtool Commands

## Global Behavior

- Commands that talk to a device accept `--device <selector>`.
- If `--device` is omitted, the tool runs discovery and auto-selects only when
  exactly one compatible RP HSM is present.
- Commands with binary or opaque result data write only the result to stdout.
- Diagnostics, warnings, ambiguity notices, and usage errors go to stderr.
- Unsupported commands or unavailable capabilities fail with non-zero exit
  status and no partial secret-bearing stdout.

## Initial Command Set

### `rphsmtool find`

- Purpose: enumerate compatible RP HSM devices
- Device selection: not required
- Stdin: none
- Stdout: structured listing of compatible devices
- Stderr: only diagnostics
- Failure cases:
  - no compatible devices found
  - host transport scan failure

### `rphsmtool status`

- Purpose: return bounded device and session status information
- Device selection: required or implicit single-match
- Stdin: none
- Stdout: structured status output only
- Stderr: diagnostics only
- Failure cases:
  - missing or ambiguous device selection
  - malformed device response
  - unsupported status surface on the connected firmware

### `rphsmtool developer-reset`

- Purpose: return a developer-mode lab device to `factory`
- Device selection: required or implicit single-match
- Stdin: none
- Stdout: structured reset result only
- Stderr: diagnostics only
- Failure cases:
  - missing or ambiguous device selection
  - connected firmware is not in developer-mode
  - developer reset command is unavailable
  - malformed device response

### `rphsmtool developer-reboot`

- Purpose: request a developer-mode reboot of the connected lab device
- Device selection: required or implicit single-match
- Stdin: none
- Stdout: structured acknowledgement only
- Stderr: diagnostics only

### `rphsmtool developer-store-fault`

- Purpose: inject a reviewed developer-mode persistence fault for lab recovery
  validation
- Device selection: required or implicit single-match
- Stdin: none
- Stdout: structured acknowledgement only
- Stderr: diagnostics only

### `rphsmtool provision-bootstrap`

- Purpose: move a factory-state or zeroized device through the reviewed
  bootstrap provisioning flow without exposing raw protocol framing
- Device selection: required or implicit single-match
- Stdin: none
- Stdout: structured provisioning result only
- Stderr: diagnostics only
- Failure cases:
  - missing or ambiguous device selection
  - missing bootstrap proof input
  - device is not in a bootstrap-eligible lifecycle state
  - bootstrap authentication failure
  - malformed device response

### `rphsmtool auth-check`

- Purpose: verify that a reviewed role can authenticate successfully
- Device selection: required or implicit single-match
- Stdin: none
- Stdout: structured session summary only
- Stderr: diagnostics only
- Failure cases:
  - missing or ambiguous device selection
  - missing or invalid proof input
  - requested role is not allowed
  - malformed device response

### Lifecycle And Session Commands

- `rphsmtool lock`
- `rphsmtool unlock`
- `rphsmtool zeroize`
- `rphsmtool logout`
- `rphsmtool enter-recovery`
- `rphsmtool recover-to-provisioned`
- `rphsmtool reactivate-recovered`

These commands are exposed because the corresponding firmware operations are
already implemented and reviewed. They require the role and lifecycle state the
firmware already enforces.

### `rphsmtool get-random`

- Purpose: return random bytes from the HSM
- Device selection: required or implicit single-match
- Stdin: none
- Stdout: raw random bytes only
- Stderr: diagnostics only
- Failure cases:
  - missing or ambiguous device selection
  - authorization failure
  - unsupported capability
  - invalid length request
  - device-side RNG failure

### Crypto And Key-Mutation Commands

- `rphsmtool sign`
- `rphsmtool verify`
- `rphsmtool import-wrapped-key`
- `rphsmtool revoke-key`
- `rphsmtool destroy-key`

These commands are exposed because the corresponding firmware operations are
already implemented and can be invoked safely through the reviewed protocol
surface.

### `rphsmtool list-keys`

- Purpose: list non-secret key records available through the approved key-store
  surface
- Device selection: required or implicit single-match
- Stdin: none
- Stdout: structured key listing only
- Stderr: diagnostics only
- Failure cases:
  - missing or ambiguous device selection
  - authorization failure
  - expired session
  - malformed device response

### `rphsmtool get-key-metadata`

- Purpose: retrieve bounded non-secret metadata for one managed key
- Device selection: required or implicit single-match
- Stdin: none
- Stdout: structured metadata only
- Stderr: diagnostics only
- Failure cases:
  - missing or ambiguous device selection
  - authorization failure
  - unknown key
  - malformed device response

## Reserved Future Commands

- `rphsmtool sym-encrypt`
- `rphsmtool sym-decrypt`
- `rphsmtool sign`
- `rphsmtool verify`

These verbs may be reserved in help or documentation, but they must not claim
to be available before the connected firmware advertises the needed
capabilities.
