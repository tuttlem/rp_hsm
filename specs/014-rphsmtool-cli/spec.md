# Feature Specification: rphsmtool CLI

**Feature Branch**: `014-rphsmtool-cli`  
**Created**: 2026-04-03  
**Status**: Draft  
**Input**: User description: "Add a Unix-style rphsmtool host CLI with --device selection, stdin/stdout data paths, capability-aligned commands, and a find command so users can access HSM operations without hand-building protocol frames."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Discover And Target A Device (Priority: P1)

An operator can locate attached RP HSM devices and select one explicitly or
implicitly without understanding the raw serial transport details.

**Why this priority**: If users cannot reliably identify a target device, every
other host operation stays tied to ad hoc developer knowledge and unsafe guesswork.

**Independent Test**: Connect one or more compatible devices, run `rphsmtool find`,
then run a read-only command with and without `--device` and confirm the tool
either selects the only compatible device or fails with a clear ambiguity error.

**Acceptance Scenarios**:

1. **Given** exactly one compatible RP HSM device is attached, **When** the user
   runs `rphsmtool find`, **Then** the tool lists that device in a machine- and
   human-readable form.
2. **Given** exactly one compatible RP HSM device is attached, **When** the user
   runs a supported command without `--device`, **Then** the tool targets that
   device automatically.
3. **Given** multiple compatible devices are attached, **When** the user runs a
   supported command without `--device`, **Then** the tool fails closed and
   instructs the user to choose a device explicitly.

---

### User Story 2 - Use Unix-Style Data Flows (Priority: P2)

An operator can use the CLI in pipelines by sending request data through stdin
and receiving command results on stdout in a bounded, script-friendly format.

**Why this priority**: A usable security product needs predictable shell
behavior so operators can automate approved workflows without custom framing
code.

**Independent Test**: Run `rphsmtool get-random`, `rphsmtool sign`, and later
compatible data-bearing commands in shell pipelines and confirm stdout contains
only the command result while diagnostics stay on stderr.

**Acceptance Scenarios**:

1. **Given** a selected device and a supported data-bearing command, **When**
   the user pipes input data into `rphsmtool`, **Then** the tool reads stdin
   exactly once and writes only the command result to stdout.
2. **Given** a supported command that does not require stdin, **When** the user
   runs the command, **Then** stdout contains only the requested result bytes or
   requested structured output.
3. **Given** an error such as ambiguity, auth failure, or malformed input,
   **When** the command fails, **Then** the tool writes diagnostics to stderr,
   returns a non-zero exit status, and emits no partial secret-bearing output
   on stdout.

---

### User Story 3 - Normalize HSM Operations For Users (Priority: P3)

An operator can invoke HSM functions through stable, capability-aligned CLI
verbs instead of manually building protocol frames.

**Why this priority**: The CLI becomes the human contract for the product and
lets the firmware evolve behind a predictable user-facing interface.

**Independent Test**: Execute representative commands such as `find`,
`get-random`, `list-keys`, `get-key-metadata`, and later `sym-encrypt` /
`sym-decrypt` only when the firmware actually supports them, and confirm the
tool exposes unavailable operations honestly.

**Acceptance Scenarios**:

1. **Given** the connected firmware does not support a requested operation,
   **When** the user runs the corresponding CLI command, **Then** the tool
   reports that the operation is unavailable instead of pretending to support it.
2. **Given** the firmware supports a requested operation, **When** the user runs
   the corresponding CLI command, **Then** the tool performs the full device
   exchange without requiring the user to know session framing or request counters.
3. **Given** the CLI is used across multiple firmware revisions, **When** a
   command surface changes, **Then** the tool reports capability mismatch
   explicitly rather than silently degrading behavior.

### Edge Cases

- What happens when no compatible RP HSM device is attached?
- What happens when multiple compatible devices are attached and `--device` is
  omitted?
- What happens when the selected device disappears during an operation?
- What happens when stdin is empty for a command that requires input data?
- What happens when stdout is redirected and the command fails partway through a
  multi-step authenticated exchange?
- What happens when a requested CLI verb exists but the connected firmware does
  not advertise the corresponding capability?

### Security Misuse Cases *(mandatory)*

- How does the tool respond to malformed, truncated, replayed, or out-of-order
  responses from the device?
- What prevents the tool from defaulting to the wrong device or leaking output
  to stdout when the user did not explicitly select a safe target?
- What secrets or sensitive state could the tool expose through logs, shell
  history, stderr, environment variables, or temporary files, and how is that
  prevented?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide a host CLI named `rphsmtool` as the canonical
  user-facing interface for supported RP HSM operations.
- **FR-002**: System MUST provide a `find` command that enumerates compatible RP
  HSM devices and returns stable selection information for each compatible target.
- **FR-003**: System MUST support a `--device` selector for commands that talk
  to a device.
- **FR-004**: System MUST automatically select a device only when exactly one
  compatible RP HSM is available; otherwise it MUST fail closed and require
  explicit device selection.
- **FR-005**: System MUST support stdout-only result emission and stderr-only
  diagnostics so commands remain safe in Unix pipelines.
- **FR-006**: System MUST support stdin-driven request data for commands whose
  primary payload is opaque user data.
- **FR-007**: System MUST expose only operations that the connected firmware
  actually supports and MUST report unavailable operations explicitly.
- **FR-008**: System MUST normalize authentication, session, replay-counter, and
  framing behavior so users do not need to construct protocol frames manually.
- **FR-009**: System MUST define a stable initial command set that includes
  device discovery, status inspection, random generation, key listing, and key
  metadata retrieval.
- **FR-010**: System MUST reserve future CLI verbs for capability-aligned data
  operations such as symmetric encryption and decryption without claiming those
  verbs are available before firmware support exists.
- **FR-011**: System MUST define fail-safe behavior for invalid state, malformed
  input, and dependency failures.
- **FR-012**: System MUST define how secret-bearing data is bounded, protected,
  and destroyed.

### Security Requirements *(mandatory)*

- **SR-001**: The CLI MUST protect device-selection integrity, session state,
  and secret-bearing request or response material at the host trust boundary.
- **SR-002**: The CLI MUST preserve the device’s authorization, anti-replay, and
  capability checks rather than bypassing or weakening them for convenience.
- **SR-003**: The CLI MUST keep diagnostics, debug output, and default logging
  free of secret-bearing data and MUST distinguish developer-only workflows from
  production-safe user operations.

### Key Entities *(include if feature involves data)*

- **Discovered Device**: A compatible RP HSM candidate with a selectable device
  path, compatibility identity, and enough metadata to distinguish it from
  other attached devices.
- **CLI Command Invocation**: A user-requested operation with verb, options,
  device selection state, stdin payload expectations, stdout output mode, and
  exit status.
- **Capability Surface**: The set of operations the connected firmware
  advertises as supported and safe for the current device state.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An operator can discover attached compatible devices and identify
  the correct target in a single command invocation without reading firmware
  source or using raw serial tools.
- **SC-002**: For supported commands, a user can complete the end-to-end
  operation through `rphsmtool` without hand-building protocol frames or
  counters.
- **SC-003**: In pipeline use, supported commands emit only the requested result
  on stdout and place diagnostics on stderr in 100% of documented error cases.
- **SC-004**: When device selection is ambiguous or the requested operation is
  unsupported by the connected firmware, the tool fails explicitly with no
  partial secret-bearing output.

## Assumptions

- The initial CLI will target the existing RP HSM transport rather than
  introducing a kernel device driver or background daemon.
- Device discovery will be bounded to interfaces the project already exposes in
  developer and production workflows.
- The first released CLI verbs will track currently implemented firmware
  capabilities instead of inventing unsupported operations.
- Future user-facing verbs such as `sym-encrypt` and `sym-decrypt` are expected
  to land in later specs once the firmware implements symmetric crypto safely.

## Security Acceptance Notes

- Acceptance must include denial behavior for missing devices, multiple-device
  ambiguity, unsupported operations, expired sessions, and malformed device
  responses.
- Any claim that a command is production-safe must exclude developer-only
  transport or reset behavior explicitly.
- Host-side convenience must not imply stronger confidentiality than the device
  or host environment actually provides.
