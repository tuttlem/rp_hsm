# Contract: Device Lifecycle State Machine

## State Set

- `factory`: device has no owner binding and no protected operations available
- `provisioned`: owner binding exists but operational capabilities are not yet
  enabled until final activation succeeds
- `operational`: owned steady state; routine protected commands may execute
- `locked`: protected commands denied pending explicit unlock or recovery
- `recovery`: restricted administrative mode for remediation only
- `zeroized`: destructive post-owner state requiring fresh provisioning

## Allowed Transitions

| Source | Target | Trigger | Required Authority | Notes |
|--------|--------|---------|--------------------|-------|
| `factory` | `provisioned` | `BeginProvisioning` | Bootstrap owner | Creates owner-bound pending record |
| `provisioned` | `operational` | `FinalizeProvisioning` | Bootstrap owner | Only after integrity checks pass |
| `operational` | `locked` | `LockDevice` | Administrator or policy trigger | Immediate denial of routine commands |
| `locked` | `operational` | `UnlockDevice` | Administrator | Clears lock condition only |
| `locked` | `recovery` | `EnterRecovery` | Recovery authority | No routine operations restored |
| `recovery` | `provisioned` | `RecoverToProvisioned` | Recovery authority | Enters reactivation-ready state only |
| `provisioned` | `operational` | `ReactivateRecoveredProvisioning` | Recovery authority | Only valid for recovery-originated reactivation |
| `recovery` | `zeroized` | `ExecuteZeroize` | Recovery authority | Destructive terminal action |
| `operational` | `zeroized` | `ExecuteZeroize` | Administrator | Destructive terminal action |
| `provisioned` | `zeroized` | `ExecuteZeroize` | Administrator | Clears incomplete bootstrap state |
| `zeroized` | `provisioned` | `BeginProvisioning` | Bootstrap owner | Treated as new claim flow |

All other transitions are denied with an explicit state error.

## Reboot Reconciliation Rules

- If no valid `pending_transition` exists, the committed state remains active.
- If a valid `pending_transition` exists without a matching committed terminal
  update, boot reconciliation moves the device into `recovery` unless the spec
  explicitly defines a safer state-specific rollback.
- If the provisioning record fails integrity validation, the device halts
  privileged command handling and exposes only recovery-safe status behavior.
- Reboot must never infer a successful administrative or destructive action
  from partially written flash.

## Command Availability Rules

| State | Public Status Commands | Provisioning Commands | Protected Operational Commands | Recovery Commands | Zeroize | Developer Reset |
|-------|------------------------|-----------------------|-------------------------------|------------------|---------|-----------------|
| `factory` | Allowed | `BeginProvisioning` only | Denied | Denied | Denied | Allowed only in `developer-mode` |
| `provisioned` | Allowed | `FinalizeProvisioning`, `ReactivateRecoveredProvisioning` | Denied | Denied | Allowed with authority | Allowed only in `developer-mode` |
| `operational` | Allowed | Denied | Allowed by policy | Denied | Allowed with authority | Allowed only in `developer-mode` |
| `locked` | Allowed | Denied | Denied | `EnterRecovery` | Denied unless policy explicitly permits | Allowed only in `developer-mode` |
| `recovery` | Allowed | Denied | Denied | Recovery-only commands | Allowed | Allowed only in `developer-mode` |
| `zeroized` | Allowed | `BeginProvisioning` only | Denied | Denied | Idempotent no-op or explicit denial | Allowed only in `developer-mode` |

## Fail-Safe Requirements

- Invalid source state for any lifecycle command returns a deterministic state
  denial and leaves the committed record unchanged.
- Repeated non-idempotent lifecycle requests return the documented replay or
  state denial rather than partially reapplying the transition.
- Recovery reactivation is denied unless recovery has explicitly placed the
  device into the reactivation-ready path.
- Authorization failure does not expose owner secrets, recovery tokens, or
  pending transition internals.
- Any flash write or integrity failure leaves the device in a non-operational
  state and requires explicit recovery or reprovisioning.
- Developer reset never appears in production command catalogs and always
  resolves to `factory`.
