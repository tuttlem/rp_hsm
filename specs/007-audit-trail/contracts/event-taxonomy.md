# Contract: Audit Event Taxonomy

## Event Classes

### Administrative

- provisioning started
- provisioning finalized
- lock requested
- unlock requested
- zeroize executed
- developer policy changed

### SecurityDenial

- role denied
- state denied
- key policy denied
- approval required
- approval stale
- command unavailable for caller/build

### LifecycleTransition

- factory -> provisioned
- provisioned -> operational
- operational -> locked
- locked -> recovery
- recovery -> provisioned
- zeroized -> factory

### PersistenceAnomaly

- audit overflow occurred
- audit storage degraded
- audit restore ambiguity detected

### ObservabilityAccess

- audit page retrieved
- audit retrieval denied
- health status retrieved

## Result Classes

- `Success`
- `Denied`
- `FailedClosed`
- `Degraded`

## Ordering Rules

- Sequence IDs are monotonic within retained history.
- Restart does not reset the logical sequence stream when persistence is intact.
- If monotonic ordering cannot be trusted after corruption or restore ambiguity,
  audit retrieval must fail closed and health status must reflect degradation.
