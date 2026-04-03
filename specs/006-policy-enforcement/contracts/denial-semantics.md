# Contract: Denial Semantics

## Goals

- preserve fail-closed behavior
- provide enough signal for safe operator recovery
- avoid acting as a privilege oracle for hostile hosts

## Denial Classes

### `command_unavailable`

Use when:

- the command is not compiled into the current build
- the command is developer-only but the build is not developer-mode
- the command family is intentionally excluded from the current feature set

### `state_denied`

Use when:

- device lifecycle state does not allow the command
- a required transition state is missing
- approval state is structurally incompatible with the current device state

### `role_denied`

Use when:

- the active or requested role is insufficient for the command
- the session is missing, expired, or replay-invalid

### `key_policy_denied`

Use when:

- the command touches a managed key whose usage mask, export policy, algorithm,
  or lifecycle state is incompatible with the requested operation

### `approval_missing`

Use when:

- the command is mapped to a protected action class and required approval is not
  yet complete

### `approval_stale`

Use when:

- a previously created approval artifact no longer matches the current policy,
  target, lifecycle state, or expiry window

### `internal_policy_error`

Use when:

- conflicting rules exist
- a required policy reference cannot be resolved
- approval persistence or reconstruction is ambiguous

## Feedback Rules

- Status responses must remain bounded and machine-consumable
- Denials may reveal the class of failure, but not:
  - hidden role hierarchy beyond the public contracts
  - secret approval material
  - raw persisted approval records
  - internal rule ordering beyond the documented matrix

## Fail-Safe Rules

- if multiple denial classes could apply, the device returns the first class in
  the documented evaluation order and still denies execution
- if the policy engine cannot determine a single valid outcome, the result is
  `internal_policy_error`
- no partial execution is allowed before a final `allow` decision is reached
