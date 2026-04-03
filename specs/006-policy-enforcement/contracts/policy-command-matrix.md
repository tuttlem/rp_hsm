# Contract: Policy Command Matrix

## Public Commands

| Command | Role | Device State | Key Context | Approval |
|---------|------|--------------|-------------|----------|
| `GetProtocolVersion` | Public | Any | No | None |
| `GetDeviceStatus` | Public | Any | No | None |
| `GetCommandCatalog` | Public | Any | No | None |
| `GetLifecycleStatus` | Public | Any | No | None |
| `GetKeyStoreStatus` | Public | Any | No | None |
| `BeginAuthentication` | Public | Any | No | None |
| `CompleteAuthentication` | Public | Any | No | None |
| `GetSessionStatus` | Public | Any | No | None |
| `GetCryptoCapabilities` | Public | Any | No | None |
| `VerifyDetached` | Public | Any | No | None |

## Bootstrap Commands

| Command | Role | Device State | Key Context | Approval |
|---------|------|--------------|-------------|----------|
| `BeginProvisioning` | Bootstrap | `factory`, `zeroized` | No | None |
| `FinalizeProvisioning` | Bootstrap | `provisioned` | No | None |

## Administrator Commands

| Command | Role | Device State | Key Context | Approval |
|---------|------|--------------|-------------|----------|
| `LockDevice` | Administrator | `operational` | No | None |
| `UnlockDevice` | Administrator | `locked` | No | None |
| `GenerateRandom` | Administrator | `operational` | No | None |
| `ExecuteZeroize` | Administrator | `provisioned`, `operational`, `recovery` | No | `destructive_admin` when dual-control is enabled, otherwise single reviewed admin path |
| `InvalidateSession` | Active session role | Any | No | None |

## Recovery Commands

| Command | Role | Device State | Key Context | Approval |
|---------|------|--------------|-------------|----------|
| `EnterRecovery` | Recovery | `locked` | No | None |
| `RecoverToProvisioned` | Recovery | `recovery` | No | `recovery_transition` when dual-control is enabled |
| `ReactivateRecoveredProvisioning` | Recovery | `provisioned` | No | `recovery_transition` if the paired recovery action required dual approval |

## Key Manager Commands

| Command | Role | Device State | Key Context | Approval |
|---------|------|--------------|-------------|----------|
| `PutPersistentKey` | Key Manager | `operational` | Yes | None in v1, but still subject to key usage and export-policy validation |
| `ListPersistentKeys` | Key Manager | `operational`, `locked`, `recovery` | No | None |
| `GetKeyMetadata` | Key Manager | `operational`, `locked`, `recovery` | Yes | None |
| `RevokePersistentKey` | Key Manager | `operational` | Yes | None |
| `DestroyPersistentKey` | Key Manager | `operational`, `locked`, `recovery` | Yes | `destructive_key` when dual-control is enabled |
| `SignDetached` | Key Manager | `operational` | Yes | None |
| `GenerateRandom` | Key Manager | `operational` | No | None |
| `ImportWrappedKey` | Key Manager | `operational` | Yes | None |

## Key Usage Overlay

When a command touches a managed key, the following additional rules apply:

- `SignDetached` requires:
  - key lifecycle state `active`
  - key algorithm compatible with signing
  - key usage mask includes signing
- `ImportWrappedKey` requires:
  - wrapping key usage mask includes wrap/import authority
  - target export policy is approved by policy
- `RevokePersistentKey` and `DestroyPersistentKey` require:
  - target key exists
  - target key lifecycle state is compatible with the requested action
- If any command-level allow rule passes but a key-usage rule fails, the final
  decision is deny.

## Developer-Mode Commands

| Command | Role | Build Gate | Approval |
|---------|------|------------|----------|
| `DeveloperResetLifecycle` | Developer | developer-mode only | None |
| `DeveloperStoreFault` | Developer | developer-mode only | None |
| `DeveloperReboot` | Developer | developer-mode only | None |

Developer-mode commands are not part of the production-visible command catalog
and are never substituted for production approval paths.
