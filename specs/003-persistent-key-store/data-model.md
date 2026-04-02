# Data Model: Persistent Key Store

## Entity: KeyStoreRecord

- Fields:
  - `record_version`: schema version for record decoding
  - `slot_id`: fixed-capacity physical slot identifier
  - `key_id`: stable logical key identifier
  - `record_revision`: monotonic revision for this key
  - `store_epoch`: monotonic store freshness epoch
  - `lifecycle_state`: `pending`, `active`, `revoked`, `pending_destroy`, or
    `destroyed`
  - `metadata`: `KeyMetadata`
  - `material`: `KeyMaterialEnvelope`
  - `integrity_tag`: bounded integrity check over the record contents
- Relationships:
  - Owns one `KeyMetadata`
  - Owns one `KeyMaterialEnvelope`
  - Belongs to one logical `PersistentKey`
- Validation rules:
  - `record_version` must be supported before the record can be trusted
  - `record_revision` must strictly increase for a given `key_id`
  - `store_epoch` must meet or exceed the accepted freshness anchor
  - `destroyed` records must not expose usable key material
  - Invalid integrity or unsupported enum values make the record unusable

## Entity: KeyMetadata

- Fields:
  - `algorithm`: supported algorithm identifier
  - `origin`: `generated`, `imported`, or future reviewed values
  - `usage_mask`: bounded bitmask for allowed operations
  - `export_policy`: `non_exportable`, `wrapped_only`, or future reviewed values
  - `persistence_class`: `volatile` or `persistent`
  - `owner_scope`: owning device or administrator scope identifier
  - `created_revision`: store revision when the key first became durable
  - `last_state_change_revision`: revision of the latest lifecycle change
- Validation rules:
  - Only reviewed algorithm and usage combinations are valid
  - `volatile` keys are never committed to the persistent store
  - `non_exportable` keys cannot later transition to a broader export policy in
    this feature
  - Metadata must fit within fixed bounded field sizes

## Entity: KeyMaterialEnvelope

- Fields:
  - `encoding`: raw internal secret form or wrapped import form identifier
  - `material_len`: bounded byte length
  - `material_bytes`: fixed-capacity storage region for secret-bearing bytes
  - `destroyed_marker`: boolean or enum indicating material has been invalidated
- Validation rules:
  - Only one encoding is active per record
  - `material_len` must stay within the fixed slot size
  - `destroyed_marker` must be set and active material bytes cleared in
    terminal destroyed records
  - Staging copies in RAM must be zeroized after validation and commit

## Entity: PersistentKey

- Fields:
  - `key_id`: stable logical identifier
  - `current_slot_id`: slot containing the latest valid record
  - `latest_revision`: highest accepted revision for this key
  - `current_state`: derived current `KeyLifecycleState`
- Relationships:
  - Resolves to one latest `KeyStoreRecord`
  - Is indexed by the `KeyStoreDirectory`
- Validation rules:
  - At most one latest valid live record exists per `key_id`
  - `current_state` is derived only from the latest valid accepted record

## Entity: KeyStoreDirectory

- Fields:
  - `store_epoch`: accepted freshness epoch for the whole store
  - `store_revision`: monotonic whole-store revision
  - `key_count`: current count of addressable persistent keys
  - `capacity`: maximum supported persistent keys
  - `latest_slots`: bounded mapping of `key_id -> slot_id`
  - `integrity_state`: result of the most recent boot scan
- Relationships:
  - Indexes many `PersistentKey` instances
  - References `FreshnessAnchor`
- Validation rules:
  - `key_count` must not exceed `capacity`
  - Boot reconstruction must ignore superseded, torn, or stale records
  - Any ambiguity in the latest valid record for a key forces safe recovery

## Entity: FreshnessAnchor

- Fields:
  - `accepted_store_epoch`: minimum store epoch considered current
  - `accepted_device_revision`: device lifecycle revision paired with the epoch
  - `anchor_integrity_tag`: integrity protection for the anchor itself
- Validation rules:
  - Must be checked before enabling normal key use
  - Epoch regression or inconsistent pairing with device state is a security
    fault, not a recoverable convenience warning
  - Failure forces the key store into a restricted recovery-required condition

## Entity: KeyStoreStatus

- Fields:
  - `store_state`: `empty`, `ready`, `degraded`, `recovery_required`, or `full`
  - `key_count`: number of current persistent keys
  - `free_slots`: remaining writable slots
  - `rollback_detected`: boolean
  - `corruption_detected`: boolean
- Validation rules:
  - `ready` is reachable only when freshness and integrity checks pass
  - `degraded` and `recovery_required` deny protected key use

## Lifecycle Transitions

- `none -> pending`: key generation/import is accepted and staged for commit
- `pending -> active`: durable write succeeds and integrity validates
- `active -> revoked`: authorized revoke commits and key use is denied
- `active -> pending_destroy`: authorized destruction begins
- `pending_destroy -> destroyed`: durable destruction record commits
- `revoked -> destroyed`: authorized destruction of a revoked key commits
- Any use/export/modify attempt against `revoked`, `pending_destroy`, or
  `destroyed` is denied
- Any torn write, stale epoch, or ambiguous latest record moves the store to a
  non-ready status requiring recovery handling

## Derived Interfaces

- `GetKeyStoreStatus`: read-only projection of store readiness, capacity, and
  corruption/rollback indicators
- `PutPersistentKey`: create or import a persistent key record with metadata
- `ListPersistentKeys`: enumerate non-secret key identities and lifecycle state
- `GetKeyMetadata`: return non-secret metadata for a specific key
- `RevokePersistentKey`: transition an active key to `revoked`
- `DestroyPersistentKey`: transition a key to `destroyed` with destructive
  clearing behavior
