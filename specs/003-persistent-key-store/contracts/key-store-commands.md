# Contract: Persistent Key Store Commands

## Command Family Scope

This feature adds persistent key-store management and status commands to the
shared protocol contract. The surface is intentionally narrow: no secret key
material is ever returned by these commands, and all destructive or state-
changing operations are explicitly authorized and replay-sensitive.

## Command Definitions

### `GetKeyStoreStatus`

- Purpose: Return non-secret status for persistent-store readiness and capacity
- Allowed states: `factory`, `provisioned`, `operational`, `locked`, `recovery`,
  `zeroized`
- Required authority: read-only public or administrator session as later policy
  defines; no secret-bearing fields
- Request payload: empty
- Response payload:
  - `store_state`
  - `key_count`
  - `free_slots`
  - `rollback_detected`
  - `corruption_detected`
- Failure modes:
  - Corrupted internal status encoding returns internal error
  - Must not include key material, owner IDs, or stale record bytes

### `PutPersistentKey`

- Purpose: Persist a newly generated or imported key with explicit metadata and
  lifecycle attributes
- Allowed states: `operational` only
- Required authority: administrator
- Request payload:
  - one-byte `key_id`
  - `algorithm`
  - `origin`
  - `usage_mask`
  - `export_policy`
  - one-byte material length
  - bounded secret-bearing key material or wrapped import payload
- Response payload:
  - `key_id`
  - resulting lifecycle state
  - committed record revision
  - store revision
- Failure modes:
  - Full store returns explicit capacity denial
  - Invalid metadata or unsupported algorithm/origin combinations return
    validation denial
  - Interrupted or failed persistence leaves the key unavailable and moves the
    store to a non-ready or recovery-required status

### `ListPersistentKeys`

- Purpose: Enumerate current persistent keys without exposing secrets
- Allowed states: `operational`, `locked`, `recovery`
- Required authority: administrator or recovery authority as policy later
  defines
- Request payload:
  - pagination or bounded offset fields if needed
- Response payload:
  - bounded list of `(key_id, algorithm, lifecycle_state, usage_mask,
    export_policy)`
- Failure modes:
  - Unknown or destroyed keys are omitted or represented only by non-secret
    tombstone state, never by secret remnants

### `GetKeyMetadata`

- Purpose: Return non-secret metadata and lifecycle state for a single key
- Allowed states: `operational`, `locked`, `recovery`
- Required authority: administrator or recovery authority
- Request payload:
  - one-byte `key_id`
- Response payload:
  - `key_id`
  - `algorithm`
  - `origin`
  - `usage_mask`
  - `export_policy`
  - `lifecycle_state`
  - `record_revision`
- Failure modes:
  - Unknown, stale, revoked-for-hidden-policy, or destroyed keys return explicit
    denial or not-found semantics without exposing raw storage contents

### `RevokePersistentKey`

- Purpose: Transition an active key to `revoked`
- Allowed states: `operational`
- Required authority: administrator
- Request payload:
  - one-byte `key_id`
  - one-byte revocation confirmation marker
- Response payload:
  - `key_id`
  - resulting lifecycle state
  - committed record revision
- Failure modes:
  - Repeated revoke returns documented state denial or idempotent acknowledgement
  - Revoked keys remain denied for use, export, or modification

### `DestroyPersistentKey`

- Purpose: Transition a key to `destroyed` and clear active secret-bearing
  storage for the live record
- Allowed states: `operational`, `recovery`
- Required authority: administrator or recovery authority
- Request payload:
  - one-byte `key_id`
  - destructive confirmation marker `0xde 0xad`
- Response payload:
  - `key_id`
  - resulting lifecycle state
  - destruction completion flags
- Failure modes:
  - Partial or interrupted destruction must leave the store in a fail-safe
    non-ready or recovery-required state
  - Destroyed keys must not be usable or exportable afterward

## Global Validation Rules

- Every state-changing key-store command is replay-sensitive.
- Secret-bearing request payloads must be validated in bounded staging buffers
  and zeroized after commit or rejection.
- Store readiness must be checked before accepting any key-use or key-management
  command other than status and recovery-safe inspection.
- `destroyed` and `revoked` records remain administratively visible only through
  non-secret metadata.
- Production images must not add broader inspection or export paths beyond the
  explicit contracts above.

## Developer-Mode Validation Controls

These controls are not part of the production command surface. They exist only
in `developer-mode` images so hardware validation can exercise persistence and
fail-safe recovery paths without adding production-visible privilege bypasses.

### `DeveloperStoreFault`

- Purpose: Inject a persisted-store fault for validation
- Allowed states: developer-mode only
- Required authority: developer
- Request payload:
  - one-byte action code
  - `0x01` => persist a corrupted store image
  - `0x02` => persist a stale-anchor rollback image
- Response payload:
  - echoed action code
- Failure modes:
  - Must return explicit internal error if the backing flash image could not be
    altered as requested

### `DeveloperReboot`

- Purpose: Reboot the device so boot-scan reconstruction can be validated
- Allowed states: developer-mode only
- Required authority: developer
- Request payload:
  - marker bytes `RST`
- Response payload:
  - empty success payload
- Failure modes:
  - Must be compiled out of production images
