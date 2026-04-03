# Research: rphsmtool CLI

## Decision 1: Build `rphsmtool` as a separate host binary alongside the existing probe

- **Decision**: Keep `probe_protocol` as the engineering validation tool and
  add a distinct `rphsmtool` binary for user-facing operations.
- **Rationale**: The probe is intentionally exhaustive, state-mutating, and
  contract-oriented. A user CLI needs stable verbs, shell-safe stdout/stderr
  behavior, and less coupling to feature-validation sequences.
- **Alternatives considered**:
  - Extend `probe_protocol` into the main CLI: rejected because probe semantics
    are validation-heavy and not a clean operator surface.
  - Replace the probe entirely with `rphsmtool`: rejected because the repo still
    needs a dedicated validation harness for feature sign-off.

## Decision 2: Use `rphsmtool find` as the canonical discovery primitive

- **Decision**: Define `find` as the explicit discovery command and use the same
  discovery logic for default device resolution when `--device` is omitted.
- **Rationale**: One discovery path prevents drift between “what the tool lists”
  and “what the tool auto-selects.” It also gives users an explicit way to
  inspect targets before running stateful commands.
- **Alternatives considered**:
  - Require `--device` for every command: rejected because single-device usage
    becomes unnecessarily awkward.
  - Implicitly choose the first matching device always: rejected because it can
    target the wrong HSM silently.

## Decision 3: Auto-select only when exactly one compatible device exists

- **Decision**: Commands without `--device` succeed only when discovery finds
  exactly one compatible device.
- **Rationale**: This is the safest Unix-friendly default. It preserves
  convenience in the common single-device case without guessing in the
  multi-device case.
- **Alternatives considered**:
  - Always choose the first enumerated device: rejected because enumeration
    order is not a safe trust primitive.
  - Never auto-select: rejected because it adds friction without increasing
    safety in the single-device case.

## Decision 4: Preserve strict stdout/stderr separation

- **Decision**: Command result bytes or requested structured output go to
  stdout; diagnostics and usage/help go to stderr.
- **Rationale**: This is necessary for shell pipelines, redirection safety, and
  avoiding partial binary output mixed with human-readable diagnostics.
- **Alternatives considered**:
  - Mixed human-readable status on stdout: rejected because it breaks pipelines.
  - Temporary output files by default: rejected because they complicate
    workflows and widen the host-side secret surface.

## Decision 5: Keep capability gating in the CLI rather than inventing a richer host contract

- **Decision**: The CLI should inspect advertised firmware capabilities and deny
  unavailable verbs explicitly rather than simulating unsupported operations.
- **Rationale**: The firmware remains the source of truth for available
  operations, and the host tool should not imply support for commands the device
  cannot perform.
- **Alternatives considered**:
  - Hard-code command availability by firmware branch or version: rejected
    because it is brittle and drifts.
  - Hide unavailable verbs entirely: rejected because explicit denial is more
    honest and easier to debug.

## Decision 6: Reuse host-side protocol/session logic rather than exposing frame construction

- **Decision**: `rphsmtool` should own authentication, session counters, and
  framing internally through host-side client helpers.
- **Rationale**: This is the main user value of the CLI. Requiring users to
  know counters, headers, or message kinds defeats the purpose of the tool.
- **Alternatives considered**:
  - Thin wrapper around raw frame input/output: rejected because it preserves
    the current usability problem.
  - Kernel-driver-first integration: rejected for now because the CLI is the
    simpler, more reviewable user contract.

## Decision 7: Start with the currently supported operation set

- **Decision**: Initial verbs should include `find`, status inspection,
  `get-random`, `list-keys`, and `get-key-metadata`, with future verbs such as
  `sym-encrypt` and `sym-decrypt` reserved for later firmware features.
- **Rationale**: The CLI should be immediately useful without overstating the
  firmware’s current capabilities.
- **Alternatives considered**:
  - Define future verbs as active now with placeholder behavior: rejected
    because it creates a misleading user surface.
  - Wait until symmetric crypto exists before adding any user CLI: rejected
    because tooling should evolve in parallel with capability growth.
