# Data Model: Secure Command Protocol

## Protocol Frame

- Purpose: Represents one complete request or response exchanged between host
  and device.
- Fields:
  - `protocol_version`: active frame version identifier
  - `message_kind`: request or response
  - `command_or_status`: command identifier for requests or status identifier
    for responses
  - `flags`: bounded control bits such as replay-sensitive or response-required
  - `payload_length`: declared byte length of payload section
  - `payload`: bounded message body
- Validation rules:
  - `protocol_version` must match a supported version
  - `payload_length` must not exceed frame capacity
  - total received bytes must match declared frame structure
  - reserved flags must be zero unless explicitly defined

## Command Definition

- Purpose: Declares the meaning and execution boundary of a supported request.
- Fields:
  - `command_id`
  - `family`
  - `request_schema`
  - `response_schema`
  - `allowed_device_states`
  - `required_session_state`
  - `replay_policy`
  - `idempotency_policy`
- Validation rules:
  - every `command_id` must be unique within the protocol version
  - every command must declare both device-state and session-state eligibility
  - replay and idempotency policies must be explicit

## Session Context

- Purpose: Represents the execution context used to decide whether a parsed
  command may proceed.
- Fields:
  - `session_state`
  - `authorization_level`
  - `freshness_context`
  - `sequence_context`
- Validation rules:
  - context may be absent only for commands explicitly marked unauthenticated
  - unauthorized or stale contexts must never advance to command execution

## Error Outcome

- Purpose: Provides a defined rejection or failure result without exposing
  unnecessary internals.
- Fields:
  - `status_code`
  - `category`
  - `retry_hint`
  - `response_payload`
- Validation rules:
  - every denial path must map to one documented error category
  - status payloads must not include secret or hidden internal state

## State Transitions

### Request Handling Pipeline

1. Bytes received
2. Frame boundary validation
3. Structural validation
4. Command lookup
5. Device/session state check
6. Replay or idempotency evaluation
7. Command execution or denial
8. Response serialization
9. Buffer clear and return to idle

### Terminal Denial States

- Invalid frame
- Unsupported version
- Unknown command
- Invalid payload
- Out-of-state request
- Unauthorized request
- Replay-denied request
- Internal failure
