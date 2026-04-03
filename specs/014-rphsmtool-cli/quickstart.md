# Quickstart: rphsmtool CLI Validation

## 1. Validate Discovery

Goal: prove operators can identify compatible devices without raw serial tools.

Sequence:

1. Connect one compatible RP HSM device
2. Run `cargo rphsmtool find`
3. Run `cargo rphsmtool status` without `--device`

Expected outcomes:

- `find` lists the compatible device cleanly
- the read-only command auto-selects the single device

## 2. Validate Ambiguity Handling

Goal: prove the tool fails closed when it cannot choose safely.

Sequence:

1. Connect more than one compatible RP HSM device
2. Run `cargo rphsmtool status` without `--device`
3. Run the same command with `--device /dev/ttyACM0`

Expected outcomes:

- the command without `--device` fails explicitly
- the command with `--device` succeeds against the chosen target only

## 3. Validate Unix-Style Output Separation

Goal: prove pipeline-safe stdout/stderr behavior.

Sequence:

1. Export `RPHSM_PROOF=BOOT`
2. Run `cargo rphsmtool developer-reset --device <selector>` if the device is not already in `factory`
3. Run `cargo rphsmtool provision-bootstrap --device <selector> --proof-env RPHSM_PROOF`
4. Export `RPHSM_PROOF=ADMIN`
5. Run `cargo rphsmtool get-random --device <selector> --bytes 32 --role administrator --proof-env RPHSM_PROOF`
6. Redirect stdout to a file
7. Force a failure such as an invalid selector and observe stderr

Expected outcomes:

- stdout contains only random bytes on success
- stderr contains only diagnostics on failure
- failure does not leave partial secret-bearing stdout output

## 4. Validate Capability-Aligned Commands

Goal: prove the CLI surface matches connected firmware support honestly.

Sequence:

1. Run capability-backed commands such as `cargo rphsmtool status`, `cargo rphsmtool get-random`, `cargo rphsmtool list-keys`, and `cargo rphsmtool get-key-metadata`
2. Attempt a reserved future command such as `cargo rphsmtool sym-encrypt`

Expected outcomes:

- supported commands execute end to end without manual frame construction
- unavailable commands fail explicitly as unsupported or unavailable

## 5. Validate Session Handling

Goal: prove the CLI hides protocol mechanics without weakening security rules.

Sequence:

1. Run a privileged command that requires authentication via `--role` and `--proof-env`
2. Continue into a longer workflow until the underlying session expires
3. Re-run the next privileged command through the CLI

Expected outcomes:

- the CLI handles authentication and counters internally
- expired sessions do not silently reuse stale authority
- follow-on commands either reauthenticate safely or fail explicitly according
  to the defined workflow

## Notes

- Commands that require authentication intentionally take proof input from an
  environment variable, not a direct command-line flag.
- `find` and `status` can be validated on a factory-state developer-mode
  device. Commands such as `get-random`, `list-keys`, and `get-key-metadata`
  also require the connected device to be in a lifecycle state that permits the
  requested role.
