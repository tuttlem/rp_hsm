# Quickstart: Persistent Key Store Validation

## 1. Validate Empty Store Reporting

Goal: confirm a fresh or zeroized device reports a non-ready or empty key-store
status without exposing ghost keys.

Sequence:

1. Boot a device with no persistent keys committed
2. Send `GetKeyStoreStatus`
3. Send `ListPersistentKeys`

Expected outcomes:

- the store reports `empty` or equivalent reviewed ready-state semantics
- key count is zero
- no secret-bearing data or phantom metadata is returned

## 2. Validate Durable Key Creation

Goal: prove a persistent key survives reboot with unchanged metadata and policy.

Sequence:

1. Start from `operational`
2. Send `PutPersistentKey` with valid metadata and allowed key material
3. Send `GetKeyMetadata`
4. Reboot the device
5. Send `GetKeyStoreStatus`
6. Send `GetKeyMetadata` again

Expected outcomes:

- the key is present before and after reboot
- metadata and lifecycle state remain unchanged
- the store remains in a ready state
- the developer-mode probe can validate this on hardware by creating a key,
  issuing a developer reboot, and re-querying the store after re-enumeration

## 3. Validate Lifecycle Enforcement

Goal: ensure revoked and destroyed keys cannot be used as active keys.

Sequence:

1. Create a persistent key
2. Send `RevokePersistentKey`
3. Attempt any later key-use or export path against that key
4. Send `DestroyPersistentKey`
5. Attempt metadata query and any key-use path again

Expected outcomes:

- revoked keys are denied for use and export
- destroyed keys are denied for use and do not expose active key material
- administrative status reflects the terminal lifecycle outcome

## 4. Validate Full-Store Handling

Goal: ensure capacity exhaustion fails closed instead of evicting keys.

Sequence:

1. Fill the persistent store to its configured capacity
2. Send one more `PutPersistentKey`
3. Re-enumerate the store

Expected outcomes:

- the extra request returns an explicit capacity error
- no prior live key is overwritten or silently evicted
- store readiness remains defined and reviewable

## 5. Validate Corruption and Torn-Write Recovery

Goal: ensure malformed or partially written records do not become usable keys.

Sequence:

1. Prepare a simulated torn or integrity-failing key record
2. Reboot or reinitialize the store scan
3. Send `GetKeyStoreStatus`
4. Attempt metadata lookup for the affected key

Expected outcomes:

- the bad record is rejected
- the store enters the documented degraded or recovery-required state if needed
- the malformed key is not treated as active
- developer-mode fault injection can be used to provoke the persisted-store
  corruption path without adding production-visible commands

## 6. Validate Rollback Detection

Goal: ensure stale persisted state does not silently restore old permissions or
older keys.

Sequence:

1. Create or update one or more persistent keys
2. Replace store contents or anchor state with an older image in a simulated
   test fixture
3. Reinitialize the key store
4. Send `GetKeyStoreStatus`

Expected outcomes:

- rollback detection is signaled explicitly
- normal key use remains denied until recovery handling occurs
- stale keys are not silently restored as active
- developer-mode fault injection can be used to validate this path on-device

## 7. Validate Secret Remnant Handling

Goal: confirm secret-bearing buffers and live records are cleared at the points
the design claims.

Sequence:

1. Create or import a persistent key
2. Revoke and destroy the key
3. Inspect only approved debug/test instrumentation or host-visible status
4. Reboot and query metadata/status again

Expected outcomes:

- host-visible interfaces never expose raw key bytes
- destroyed keys remain unavailable after reboot
- tests prove staging buffers and current live material regions were cleared on
  the documented destruction path
