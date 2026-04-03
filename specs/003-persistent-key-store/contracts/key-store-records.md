# Contract: Persistent Key Store Records

## Record Layout Goals

The persistent key store uses a bounded flash record format that is explicit,
versioned, and rejectable. A record is trusted only when every required field,
enum, length, freshness value, and integrity tag validates.

Current implementation bounds:

- up to 8 live persistent keys
- up to 24 journal records in the modeled append-only log
- bounded material payload sized to fit the protocol frame limits used by the
  current command transport

## Record Types

### `KeyStoreHeader`

- Fields:
  - `magic`
  - `record_version`
  - `record_type`
  - `payload_len`
- Validation:
  - `magic` and `record_version` must match the supported schema
  - `payload_len` must fit within the fixed flash slot

### `PersistentKeyRecord`

- Fields:
  - `slot_id`
  - `key_id`
  - `record_revision`
  - `store_epoch`
  - `lifecycle_state`
  - `algorithm`
  - `origin`
  - `usage_mask`
  - `export_policy`
  - `material_encoding`
  - `material_len`
  - `material_bytes`
  - `integrity_tag`
- Validation:
  - enum values must be recognized
  - `material_len` must not exceed the slot payload bound
  - `record_revision` must advance monotonically for the same `key_id`
  - `store_epoch` must satisfy the accepted freshness anchor
  - `destroyed` records must encode cleared or invalidated live material bytes

### `StoreAnchorRecord`

- Fields:
  - `accepted_store_epoch`
  - `accepted_device_revision`
  - `store_revision`
  - `integrity_tag`
- Validation:
  - anchor integrity must validate before normal store use
  - epoch regression or mismatched device revision forces recovery-required
    status

## Boot Reconstruction Rules

1. Scan every record slot in address order.
2. Reject truncated, malformed, or integrity-failing records immediately.
3. For each `key_id`, keep only the latest record with the highest valid
   revision and accepted epoch.
4. If two records claim the same `key_id` and revision with different payloads,
   mark the store as corrupted and deny normal use.
5. If the store anchor is stale, missing, or inconsistent with device state,
   mark the store as rollback-detected and deny normal use.

## Update Rules

1. Validate the administrative request and stage the new record in RAM.
2. Write the new `PersistentKeyRecord` to the next appendable slot.
3. Verify the written record by rereading and checking integrity.
4. Update the `StoreAnchorRecord` with the new accepted revision and epoch.
5. Zeroize staging buffers and release the old live mapping only after the new
   record and anchor both validate.

## Fail-Safe Rules

- If the key record write succeeds but the anchor update fails, the store enters
  a non-ready state until recovery resolves the mismatch.
- If a record cannot be decoded at boot, it is ignored and counted toward
  corruption detection rather than guessed into validity.
- If capacity is exhausted, no existing live key is overwritten implicitly.
- If destroy is interrupted, the key remains unavailable until recovery or a
  fresh terminal destroyed record is committed.
