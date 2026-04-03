# Data Model: Policy Enforcement

## Entity: PolicyProfile

Represents the active device-local policy profile for the current firmware
release.

### Fields

- `profile_version` (`u8`)
- `policy_revision` (`u32`)
- `dual_control_enabled` (`bool`)
- `protected_action_mask` (`u16`)
- `developer_commands_visible` (`bool`)

### Validation Rules

- `profile_version` must match the reviewed policy schema version
- `policy_revision` must increase monotonically on persisted policy changes
- `protected_action_mask` may only reference reviewed protected action classes
- if the profile cannot be parsed or validated, policy evaluation fails closed

## Entity: PolicyRule

Represents one explicit allow/deny rule entry for a command family or protected
action.

### Fields

- `command_id` (`u8`)
- `required_role` (`enum`: `public`, `bootstrap`, `administrator`, `recovery`, `key_manager`, `developer`)
- `allowed_device_states` (`set<DeviceState>`)
- `requires_key_context` (`bool`)
- `required_usage_mask` (`u8`, optional)
- `allowed_key_lifecycle_states` (`set<KeyLifecycleState>`, optional)
- `approval_class` (`enum`: `none`, `destructive_admin`, `destructive_key`, `recovery_transition`)
- `developer_only` (`bool`)

### Validation Rules

- every security-relevant command must map to exactly one policy rule entry
- a `developer_only` rule must not be visible when developer-mode is absent
- rules that reference key context must identify required usage and allowed key
  lifecycle states
- conflicting or duplicate rule definitions invalidate the policy profile

## Entity: ApprovalTicket

Represents a bounded approval artifact for a protected action.

### Fields

- `ticket_id` (`u32`)
- `approval_class` (`enum`)
- `target_binding` (`enum`: `device`, `key_id`, `transition_id`)
- `target_id` (`u32`)
- `initiator_role` (`AuthorityRole`)
- `confirmer_role` (`AuthorityRole`)
- `policy_revision` (`u32`)
- `device_revision` (`u32`)
- `expires_after_ticks` (`u16`)
- `state` (`enum`: `pending`, `confirmed`, `consumed`, `invalidated`)

### Validation Rules

- `ticket_id` must be unique within the bounded approval store
- `policy_revision` and `device_revision` must match current persisted values
  when the ticket is consumed
- `state=confirmed` is required before a protected action executes
- expired, mismatched, or reused tickets are invalidated and cannot be reused

### State Transitions

- `pending -> confirmed`: second required approval is recorded
- `pending -> invalidated`: timeout, policy revision change, reboot ambiguity,
  lifecycle change, or explicit invalidation
- `confirmed -> consumed`: protected action executes successfully
- `confirmed -> invalidated`: any prerequisite becomes stale before execution

## Entity: PolicyDecision

Represents the result of evaluating a request against the policy engine.

### Fields

- `command_id` (`u8`)
- `decision` (`enum`: `allow`, `deny`)
- `denial_class` (`enum`: `none`, `command_unavailable`, `state_denied`, `role_denied`, `key_policy_denied`, `approval_missing`, `approval_stale`, `internal_policy_error`)
- `approval_ticket_id` (`u32`, optional)

### Validation Rules

- `allow` requires all applicable rule checks to pass
- `approval_ticket_id` may be present only when the command touches a protected
  action class
- any ambiguity results in `deny`

## Entity: KeyPolicyContext

Represents the managed-key facts needed for policy evaluation.

### Fields

- `key_id` (`u8`)
- `algorithm` (`KeyAlgorithm`)
- `origin` (`KeyOrigin`)
- `usage_mask` (`u8`)
- `export_policy` (`ExportPolicy`)
- `lifecycle_state` (`KeyLifecycleState`)
- `record_revision` (`u32`)

### Validation Rules

- commands that touch a key must supply a key context or be denied
- requested operation class must be compatible with `usage_mask`
- lifecycle state must be compatible with the policy rule and command class

## Entity: ProtectedActionClass

Represents the small reviewed set of actions that require stronger approval.

### Fields

- `name` (`enum`: `execute_zeroize`, `destroy_persistent_key`, `recovery_transition`)
- `dual_control_eligible` (`bool`)
- `target_scope` (`enum`: `device`, `key`, `transition`)

### Validation Rules

- only reviewed protected action classes may exist in v1
- a command mapped to a protected action class must not execute without the
  required approval state

## Relationships

- `PolicyProfile` governs all `PolicyRule` evaluation
- `PolicyRule` may require a `KeyPolicyContext`
- `PolicyRule` may require an `ApprovalTicket`
- `ApprovalTicket` binds to one `ProtectedActionClass`
- `PolicyDecision` is produced from `PolicyProfile`, `PolicyRule`, session
  state, device state, optional `KeyPolicyContext`, and optional
  `ApprovalTicket`
