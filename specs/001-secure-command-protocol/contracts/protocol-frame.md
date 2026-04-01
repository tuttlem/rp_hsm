# Contract: Protocol Frame v1

## Overview

Protocol v1 is a bounded binary request/response contract between one host and
the RP2350 HSM firmware. Every exchange is composed of exactly one request frame
and zero or one response frame. A request is never partially executed.

## Request Frame Shape

| Field | Meaning | Rule |
|-------|---------|------|
| Version | Protocol version identifier | MUST equal the active supported version |
| Kind | Message kind | MUST indicate request |
| Command ID | Requested command | MUST map to a documented command |
| Flags | Command handling modifiers | MUST use only defined bits |
| Payload Length | Declared payload byte count | MUST not exceed protocol maximum |
| Payload | Command-specific body | MUST match command schema exactly |

## Response Frame Shape

| Field | Meaning | Rule |
|-------|---------|------|
| Version | Protocol version identifier | MUST match request version when possible |
| Kind | Message kind | MUST indicate response |
| Status Code | Outcome identifier | MUST map to a documented result |
| Flags | Response modifiers | MUST use only defined bits |
| Payload Length | Declared payload byte count | MUST not exceed protocol maximum |
| Payload | Result body | MUST match documented success or error schema |

## Initial Command Families

| Family | Purpose | Authorization Baseline |
|--------|---------|------------------------|
| Discovery | Identify protocol compatibility and device command availability | Unauthenticated but state-bounded |
| Status | Report approved non-secret protocol/device status | Unauthenticated or minimally scoped |
| Reserved Administrative | Placeholder for later provisioning and control commands | Denied until later features enable them |

## Required Result Categories

| Category | Meaning |
|----------|---------|
| Success | Request was valid and completed |
| Format Error | Frame was malformed, truncated, or oversized |
| Version Error | Version is unsupported |
| Command Error | Command identifier is unknown |
| Validation Error | Frame is structurally valid but payload is invalid |
| State Error | Command is not allowed in current device state |
| Authorization Error | Command requires session authority not currently present |
| Replay Error | Request violates duplicate or freshness policy |
| Internal Error | Device could not complete an otherwise valid request safely |

## Contract Rules

- Unsupported versions MUST be rejected explicitly.
- Unknown commands MUST be rejected explicitly.
- Reserved fields and reserved flags MUST be rejected when non-zero unless later
  revisions define them.
- Response payloads MUST omit internal state not needed by the caller.
- Future versions MAY define new commands and fields, but v1 firmware MUST deny
  any request it cannot validate completely.
