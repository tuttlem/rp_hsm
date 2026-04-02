# Research: Secure Command Protocol

## Decision 1: Use a fixed-header, length-prefixed binary frame

- Decision: Define protocol frames with a compact fixed header followed by a
  bounded payload length and payload bytes.
- Rationale: A fixed-header binary frame is easy to parse deterministically in
  `no_std` firmware, keeps frame validation explicit, and avoids ambiguous text
  parsing behavior.
- Alternatives considered:
  - Text protocol: rejected because it expands parser complexity and increases
    ambiguity around delimiters and malformed input handling.
  - Self-describing variable schema: rejected for v1 because the review surface
    is too large for the first security boundary feature.

## Decision 2: Keep the protocol core transport-agnostic

- Decision: Implement the protocol as a transport-agnostic firmware module that
  consumes bytes and emits bounded request/response outcomes.
- Rationale: The current repo uses USB CDC during bring-up, but the command
  protocol should survive future transport changes without reworking the parser
  or authorization model.
- Alternatives considered:
  - Bind protocol rules directly to USB serial behavior: rejected because it
    would leak transport assumptions into core security logic.
  - Delay protocol work until the final transport is chosen: rejected because
    the command model itself is a prerequisite for later features.

## Decision 3: Start with a minimal bootstrap command catalog

- Decision: The first command catalog will cover protocol discovery and safe
  bootstrap operations only, such as version discovery, device status, and
  explicit denial outcomes for unauthorized families.
- Rationale: The first protocol release should prove safe framing, parse
  outcomes, and authorization boundaries before provisioning or key operations
  are added.
- Alternatives considered:
  - Define a broad future-facing command surface now: rejected because it would
    force unclear authorization and state rules too early.
  - Implement only a ping command: rejected because it would not exercise the
    state and authorization metadata required by the spec.

## Decision 4: Deny unknown versions and unknown command identifiers explicitly

- Decision: Unknown protocol versions and unknown command identifiers will
  produce defined rejection outcomes rather than silent ignore behavior.
- Rationale: Explicit denial is easier to test, easier to audit, and avoids
  accidental downgrade or probing ambiguity.
- Alternatives considered:
  - Ignore unknown commands: rejected because it hides security-relevant parser
    behavior from both clients and reviewers.
  - Best-effort forward compatibility: rejected for v1 because it complicates
    validation and state safety.

## Decision 5: Separate parse validity from execution eligibility

- Decision: Request handling will proceed in ordered stages: framing validation,
  semantic validation, command lookup, state/authorization check, then execution
  dispatch.
- Rationale: This keeps denial reasons reviewable and prevents partially valid
  requests from reaching sensitive logic.
- Alternatives considered:
  - Inline command-specific validation inside handlers: rejected because it
    spreads denial logic and increases the chance of inconsistent checks.
  - Pre-authorize before full parse: rejected because authorization metadata is
    carried by the parsed command identity and state context.

## Decision 6: Treat replay control as command-class metadata

- Decision: The protocol will define duplicate and replay handling rules, but
  strict replay protection will be attached to command metadata and later session
  features rather than forced uniformly across all commands.
- Rationale: Some requests are safe to repeat while others must be single-use;
  the protocol needs an explicit place for that distinction now.
- Alternatives considered:
  - Ignore replay until authentication is built: rejected because the spec
    requires replay-sensitive behavior to be modeled from the start.
  - Make every request single-use immediately: rejected because it would impose
    session machinery that does not exist yet.

## Decision 7: Use bounded static buffers for request, response, and parser state

- Decision: All frame parsing and serialization will use fixed-capacity buffers
  sized by protocol limits and cleared on exit paths.
- Rationale: This matches the constitution requirement for explicit secret and
  buffer lifecycle control and fits the `no_std` firmware environment.
- Alternatives considered:
  - Heap-backed parsing: rejected because allocator behavior is unnecessary and
    adds failure modes.
  - Unbounded streaming accumulation: rejected because it conflicts with
    deterministic memory use and denial behavior.
