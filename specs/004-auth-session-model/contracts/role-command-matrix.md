# Contract: Role to Command Matrix

## Public Commands

- `GetProtocolVersion`
- `GetDeviceStatus`
- `GetCommandCatalog`
- `GetLifecycleStatus`
- `GetKeyStoreStatus`
- `BeginAuthentication`
- `CompleteAuthentication`
- `GetSessionStatus`

## Bootstrap Role

- `BeginProvisioning`
- `FinalizeProvisioning`

## Administrator Role

- `LockDevice`
- `UnlockDevice`
- `ExecuteZeroize`
- `InvalidateSession` for the active administrator session

## Recovery Role

- `EnterRecovery`
- `RecoverToProvisioned`
- `ReactivateRecoveredProvisioning`

## Key Manager Role

- `PutPersistentKey`
- `ListPersistentKeys`
- `GetKeyMetadata`
- `RevokePersistentKey`
- `DestroyPersistentKey`

## Developer-Mode Only

- `DeveloperResetLifecycle`
- `DeveloperStoreFault`
- `DeveloperReboot`

## Mapping Rules

- Public reachability does not imply privileged execution. `CompleteAuthentication`
  is public only because it is the boundary-crossing step into an authenticated
  session.
- Commands not listed for a role are denied to that role.
- If a command requires both a role and a lifecycle state, both must match.
- Production builds must not include developer-mode commands in the visible or
  executable catalog.
