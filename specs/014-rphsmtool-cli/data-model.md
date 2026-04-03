# Data Model: rphsmtool CLI

## Entity: Discovered Device

- **Purpose**: Represents a compatible RP HSM candidate visible to the host CLI.
- **Fields**:
  - `device_path`: host-visible selector used with `--device`
  - `transport_kind`: serial or other supported transport class
  - `compatibility_status`: compatible, incompatible, or unknown
  - `display_name`: human-readable description for operators
  - `device_identity`: optional stable identity when available from the device
  - `developer_mode_present`: whether the connected surface appears to expose
    developer-only commands
- **Validation rules**:
  - `device_path` must be stable enough for immediate operator selection
  - incompatible or unknown targets must never be auto-selected
- **Relationships**:
  - one `Discovered Device` may become the selected target for one
    `CLI Invocation`

## Entity: Device Selection Result

- **Purpose**: Records the outcome of resolving the target device for a command.
- **Fields**:
  - `selection_mode`: explicit, implicit-single-match, none, ambiguous
  - `selected_device`: optional `Discovered Device`
  - `candidate_count`: number of compatible candidates found
  - `failure_reason`: optional missing-device, ambiguous-device, invalid-selector,
    or incompatible-device reason
- **Validation rules**:
  - implicit selection is valid only when `candidate_count == 1`
  - ambiguous or missing outcomes must block device commands
- **State transitions**:
  - `none` -> `explicit`
  - `none` -> `implicit-single-match`
  - `none` -> `ambiguous`
  - `none` -> `missing`

## Entity: CLI Invocation

- **Purpose**: Represents one user command execution.
- **Fields**:
  - `command_name`
  - `arguments`
  - `device_requirement`: required, optional, none
  - `stdin_mode`: none, optional-bytes, required-bytes
  - `stdout_mode`: raw-bytes or structured-text
  - `stderr_diagnostics`: enabled
  - `exit_status`: success or classified failure
- **Validation rules**:
  - commands requiring a device must not proceed without a successful
    `Device Selection Result`
  - commands requiring stdin must fail cleanly on empty or unreadable input
  - stdout must not contain diagnostics or partial error data

## Entity: Capability Surface

- **Purpose**: Represents the operations the connected firmware advertises as
  supported for the current device state.
- **Fields**:
  - `service_version`
  - `public_operations`
  - `privileged_operations`
  - `size_limits`
  - `developer_only_operations_present`
- **Validation rules**:
  - a CLI verb must not execute unless its required capability is present
  - unavailable capabilities must produce explicit operator-visible denial
- **Relationships**:
  - one `Capability Surface` constrains one or more `CLI Invocation` decisions

## Entity: Session Context

- **Purpose**: Tracks the authenticated context needed to perform a privileged
  command without exposing protocol mechanics to the user.
- **Fields**:
  - `role`
  - `session_id`
  - `next_request_counter`
  - `expires_in`
  - `validity_state`: active, expired, invalidated
- **Validation rules**:
  - request counters must be monotonic
  - expired or invalidated contexts must not be reused
  - session context must remain transient to the process unless a later feature
    explicitly defines persistence
- **State transitions**:
  - `active` -> `expired`
  - `active` -> `invalidated`
  - `expired` -> replaced by a fresh session

## Entity: Command Output Contract

- **Purpose**: Defines what a user-facing command may emit.
- **Fields**:
  - `stdout_payload`
  - `stderr_message`
  - `exit_code`
  - `secret_bearing`: yes or no
- **Validation rules**:
  - success-path stdout must contain only the requested result
  - stderr must not contain secret-bearing material
  - failure must not emit partial secret-bearing stdout
