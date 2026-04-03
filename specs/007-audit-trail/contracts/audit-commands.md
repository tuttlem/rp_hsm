# Contract: Audit And Health Commands

## Public/Approved Commands

### `GetHealthStatus`

- **Purpose**: Return approved non-secret device health information.
- **Request**:
  - `command_id`: `0x0c`
  - `payload`: empty
- **Response Payload**:
  - `device_state: u8`
  - `session_state: u8`
  - `key_store_state: u8`
  - `audit_store_state: u8`
  - `audit_event_count: u16`
  - `audit_overflow_detected: u8`
  - `rollback_detected: u8`
  - `corruption_detected: u8`
  - `policy_revision: u32`
- **Authorization**:
  - publicly available in v1
- **Failures**:
  - validation error for malformed requests
  - bounded denial class for disallowed visibility
  - bounded degraded-state response when audit store cannot be trusted

### `GetAuditPage`

- **Purpose**: Retrieve a bounded page of audit events.
- **Request**:
  - `command_id`: `0x0d`
- **Request Payload**:
  - `start_sequence: u32`
  - `max_events: u8`
- **Response Payload**:
  - `returned_count: u8`
  - `next_sequence_present: u8`
  - `next_sequence: u32` when present
  - repeated bounded `AuditEvent` entries
- **Authorization**:
  - `administrator` or `recovery`
- **Failures**:
  - authorization denial for insufficient role
  - validation error for malformed request payload
  - bounded degraded-state denial when audit history is ambiguous/corrupt

## Bounded Audit Event Encoding

Each entry in `GetAuditPage` uses:

- `sequence_id: u32`
- `event_class: u8`
- `event_code: u8`
- `device_revision: u32`
- `lifecycle_state: u8`
- `actor_role: u8`
- `session_state: u8`
- `result_class: u8`
- `detail_len: u8`
- `detail_bytes[detail_len]`

## Recording Rules

The firmware must emit audit events for:

- provisioning begin/finalize
- lock/unlock
- recovery entry/exit/reactivation
- zeroize
- developer reset and developer policy changes in developer builds
- authentication lockout and explicit session invalidation
- policy denials and approval-required / approval-stale outcomes
- wrapped import, revoke, destroy, and signing attempts where policy requires audit
- audit retrieval attempts and denied retrieval attempts

## Redaction Rules

Audit detail bytes must never contain:

- key material
- authentication proof bytes
- raw wrapped-key envelopes
- approval ticket secrets or replay counters
- unrestricted internal debug buffers
