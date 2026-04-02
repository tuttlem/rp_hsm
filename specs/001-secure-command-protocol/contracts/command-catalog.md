# Contract: Command Catalog v1

## Command Metadata Schema

Each command definition in protocol v1 must declare:

- command ID
- family
- request payload shape
- success response shape
- failure response categories
- allowed device states
- required session state
- replay policy
- idempotency policy

## Bootstrap Command Set

### `GetProtocolVersion`

- Purpose: Returns the active protocol version and compatibility information.
- Allowed device states: any non-failed state
- Required session state: none
- Replay policy: repeatable
- Idempotency policy: idempotent

### `GetDeviceStatus`

- Purpose: Returns bounded non-secret protocol/device status relevant to command
  negotiation.
- Allowed device states: any state that permits public status exposure
- Required session state: none
- Replay policy: repeatable
- Idempotency policy: idempotent

### `GetCommandCatalog`

- Purpose: Returns the bounded list of currently exposed command identifiers and
  their coarse access requirements.
- Allowed device states: operationally safe states only
- Required session state: none for public entries; restricted entries may be
  omitted or summarized
- Replay policy: repeatable
- Idempotency policy: idempotent

## Reserved Families

These families exist in the protocol model now but are not executable until
later features define them:

- Provisioning
- Administration
- Key Management
- Cryptographic Operations
- Audit
- Firmware Update

Requests targeting reserved families before enablement MUST return defined
denial outcomes instead of silent ignore behavior.
