# Data Model: Audit Trail

## AuditEvent

- **Purpose**: One bounded persisted record describing a security-relevant
  occurrence.
- **Fields**:
  - `sequence_id: u32`
  - `event_class: AuditEventClass`
  - `event_code: AuditEventCode`
  - `device_revision: u32`
  - `lifecycle_state: DeviceState`
  - `actor_role: AuthorityRole`
  - `session_kind: SessionState`
  - `result_class: AuditResultClass`
  - `detail_len: u8`
  - `detail: [u8; <= MAX_AUDIT_DETAIL_LEN]`
- **Validation**:
  - `detail_len` must not exceed the bounded detail capacity
  - `detail` is non-secret and schema-specific to `event_code`
  - event encoding must fit the bounded wire and persistence record limits
- **State transitions**:
  - Created on security-relevant action
  - Persisted to journal
  - Eligible for retrieval until aged out by retention

## AuditEventClass

- **Purpose**: High-level taxonomy for review and retention.
- **Values**:
  - `Administrative`
  - `SecurityDenial`
  - `LifecycleTransition`
  - `PersistenceAnomaly`
  - `ObservabilityAccess`

## AuditRecordSet

- **Purpose**: The bounded retained audit history.
- **Fields**:
  - `head_sequence: u32`
  - `tail_sequence: u32`
  - `event_count: u16`
  - `capacity: u16`
  - `overflow_count: u32`
  - `corruption_detected: bool`
  - `retrieval_locked: bool`
- **Validation**:
  - `event_count <= capacity`
  - ordering must remain monotonic unless the store is marked degraded
  - retrieval is denied when corruption/ambiguity prevents trustworthy replay

## AuditRetrievalCursor

- **Purpose**: Represents the caller’s current position within retained history.
- **Fields**:
  - `start_sequence: u32`
  - `max_events: u8`
  - `next_sequence: Option<u32>`
  - `truncated: bool`
- **Validation**:
  - `max_events` bounded to fit one protocol response
  - `start_sequence` lower than `tail_sequence` resolves to current oldest
    retained event rather than an invalid partial read

## HealthStatusView

- **Purpose**: Redacted operational summary safe for the approved caller.
- **Fields**:
  - `device_state: DeviceState`
  - `key_store_state: KeyStoreState`
  - `session_state: SessionState`
  - `policy_revision: u32`
  - `audit_store_state: AuditStoreState`
  - `audit_events_retained: u16`
  - `audit_overflow_detected: bool`
  - `rollback_detected: bool`
  - `corruption_detected: bool`
- **Validation**:
  - No key material, proofs, approval ticket IDs, or raw event details
  - Role-specific output may omit some fields, but never add secrets

## RetentionPolicy

- **Purpose**: Encodes the bounded retention behavior.
- **Fields**:
  - `capacity: u16`
  - `mode: RetentionMode`
  - `overflow_event_enabled: bool`
- **Values**:
  - `RetentionMode::OverwriteOldest`
- **Validation**:
  - Overflow behavior must be deterministic and documented
  - If an overflow event cannot itself be retained, health status must still
    reflect that overflow occurred

## Relationships

- `AuditRecordSet` contains many `AuditEvent`
- `AuditRetrievalCursor` pages through `AuditRecordSet`
- `HealthStatusView` summarizes `AuditRecordSet` and existing device state
- `RetentionPolicy` governs how `AuditRecordSet` evolves at capacity
