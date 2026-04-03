# Feature Specification: Persistent Key Store

**Feature Branch**: `003-persistent-key-store`  
**Created**: 2026-04-01  
**Status**: Draft  
**Input**: User description: "Define persistent key storage for the RP2350 HSM including key metadata, key import and generation records, lifecycle state, deletion, revocation, and anti-rollback handling"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Durable Key Retention (Priority: P1)

As a device owner, I need keys and their ownership attributes to survive normal
device restarts so that security operations remain trustworthy across the
product lifecycle.

**Why this priority**: Persistent key handling is central to whether the device
functions as an HSM rather than a temporary crypto endpoint.

**Independent Test**: Create or import allowed keys, restart the device, and
confirm that the stored keys remain present with the same attributes and usage
restrictions.

**Acceptance Scenarios**:

1. **Given** an authorized key is created or imported successfully, **When** the
   device restarts, **Then** the key remains available with the same declared
   metadata and lifecycle state.
2. **Given** key persistence fails partway through a write, **When** the device
   resumes operation, **Then** the key store remains in a safe and consistent
   state without partial key exposure.

---

### User Story 2 - Enforced Key Lifecycle Rules (Priority: P2)

As a security administrator, I need each stored key to carry explicit lifecycle
state and policy attributes so that the device can enforce how the key may be
used, changed, or retired.

**Why this priority**: Persistent storage without enforceable metadata creates
hidden behavior and weakens authorization and policy features that come later.

**Independent Test**: Attempt to use, modify, revoke, and delete stored keys in
different lifecycle states and confirm that each action is accepted or denied
according to declared rules.

**Acceptance Scenarios**:

1. **Given** a key is marked as revoked or destroyed, **When** a client attempts
   to use it, **Then** the device denies the action and reports the key as
   unavailable for that operation.
2. **Given** a key is marked as non-exportable, **When** a client requests an
   export operation, **Then** the device denies the request without exposing key
   material.

---

### User Story 3 - Safe Storage Recovery (Priority: P3)

As a product owner, I need the device to detect corruption, rollback attempts,
or invalid persisted records so that the key store cannot silently accept stale
or unsafe state.

**Why this priority**: A key store that cannot detect invalid persisted state
undermines the trustworthiness of every later cryptographic feature.

**Independent Test**: Present stale, corrupted, or inconsistent stored key
records and confirm that the device rejects them safely and preserves defined
recovery behavior.

**Acceptance Scenarios**:

1. **Given** the device detects key store data older than the accepted security
   state, **When** it initializes persistent storage, **Then** it denies normal
   key use until the defined recovery path is followed.
2. **Given** the device detects corrupted key metadata, **When** it evaluates
   the record, **Then** it rejects the record without treating it as a valid
   usable key.

### Edge Cases

- A key record reaches the maximum supported metadata size.
- Deletion or revocation is requested for a key that is already in that state.
- The key store is full when a new authorized key is requested.
- Two administrative operations target the same key in close succession.
- A device restart occurs after metadata is updated but before all related state
  is finalized.

### Security Misuse Cases *(mandatory)*

- An attacker attempts to replace current key state with an older persisted
  record to restore previously valid permissions.
- An attacker attempts to inject malformed key metadata to confuse lifecycle
  enforcement.
- An attacker attempts to recover deleted or revoked key material through
  storage remnants or administrative responses.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST provide persistent storage for keys that are
  intended to survive device restart or power loss.
- **FR-002**: The system MUST associate each stored key with explicit metadata
  including origin, lifecycle state, allowed usage, and export policy.
- **FR-003**: The system MUST preserve the relationship between a stored key and
  its metadata across restart and normal operation.
- **FR-004**: The system MUST define lifecycle actions for key creation, import,
  activation, revocation, deletion, and destruction.
- **FR-005**: The system MUST deny key use, export, or modification when those
  actions conflict with the key's current lifecycle state or policy attributes.
- **FR-006**: The system MUST define fail-safe behavior for corrupted records,
  interrupted updates, invalid metadata, storage exhaustion, and persistence
  failures.
- **FR-007**: The system MUST define how secret-bearing key material, wrapped
  import data, and transitional buffers are bounded, protected, and destroyed
  when no longer needed.
- **FR-008**: The system MUST detect and reject stored key state that does not
  satisfy the accepted freshness and integrity rules for the device.
- **FR-009**: The system MUST ensure destructive lifecycle actions remove or
  permanently disable the affected key according to the declared policy outcome.

### Security Requirements *(mandatory)*

- **SR-001**: The feature MUST protect persistent key material and metadata from
  unauthorized use, disclosure, or silent reinterpretation.
- **SR-002**: The feature MUST ensure that stale or rolled-back persisted state
  cannot silently restore broader permissions or older secrets.
- **SR-003**: The feature MUST prohibit responses, logs, or administrative
  status output from revealing secret key material or recoverable remnants.

### Key Entities *(include if feature involves data)*

- **Stored Key Record**: The persisted representation of a key and the metadata
  needed to authorize and manage it.
- **Key Lifecycle State**: The current management condition of a key, such as
  active, revoked, pending destruction, or destroyed.
- **Key Policy Attribute**: A declared property such as allowed usage, origin,
  exportability, or administrative controls that affects how the key may be
  handled.
- **Persistence Freshness Evidence**: The information used to decide whether a
  stored record is current enough to trust for normal operation.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of persisted keys retain their declared metadata and allowed
  lifecycle state across restart under normal operating conditions.
- **SC-002**: 100% of revoked, deleted, corrupted, or stale key records are
  denied for normal use.
- **SC-003**: Reviewers can trace every stored key state to a documented set of
  allowed management actions and forbidden actions.
- **SC-004**: Administrative teams can determine whether a key is usable,
  revoked, or destroyed without relying on undocumented storage behavior.

## Assumptions

- Only keys explicitly marked for persistence are stored across restart.
- Key backup or migration outside the device is a separate feature and not part
  of this initial persistent store specification.
- Lifecycle state applies to the key record as managed by the device, even when
  imported material originated elsewhere.
- Storage capacity is finite and must be managed through explicit policy rather
  than silent eviction.

## Security Acceptance Notes

- Acceptance coverage must prove denial of stale, corrupted, unauthorized, and
  post-destruction key use.
- Any persistence freshness guarantee must document what evidence the device
  relies on rather than implying perfect rollback resistance from firmware
  alone.
- The specification must not imply secure archival, escrow, or backup recovery
  beyond the device-managed key store scope.
