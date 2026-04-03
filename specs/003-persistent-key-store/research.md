# Research: Persistent Key Store

## Persistent Record Strategy

- Decision: Use an append-only flash journal of fixed-size key-store records
  with a compact in-memory index rebuilt at boot.
- Rationale: Append-only writes avoid in-place partial update hazards, make torn
  writes detectable, and give reboot recovery a clear rule: trust only the
  latest fully valid record per key slot.
- Alternatives considered: In-place overwrite of a single key table was
  rejected because power loss could leave a key record half-updated with no
  trustworthy prior image.

## Key Identity and Slot Allocation

- Decision: Give each persistent key a stable `key_id` and a fixed-capacity slot
  assignment, while allowing multiple journal entries over time for the same
  key.
- Rationale: Stable identifiers support lifecycle transitions, auditability, and
  policy checks even as records are rewritten. Fixed capacity keeps RAM and boot
  scan costs bounded on RP2350.
- Alternatives considered: Variable unbounded identifiers discovered only by
  scanning payloads were rejected because they complicate lookup bounds and make
  capacity failure less deterministic.

## Lifecycle Modeling

- Decision: Model key lifecycle explicitly as `pending`, `active`, `revoked`,
  `pending_destroy`, and `destroyed`, with command permissions derived from that
  state and from policy flags.
- Rationale: Persistence without explicit lifecycle turns revocation and
  destruction into informal conventions. Explicit states keep later crypto and
  policy features reviewable.
- Alternatives considered: A minimal active/deleted boolean was rejected
  because it cannot distinguish safe denial semantics for revoke, destroy, and
  interrupted destructive actions.

## Metadata and Policy Layout

- Decision: Store algorithm, origin, usage mask, export policy, persistence
  class, lifecycle state, and freshness epoch as part of each key record, with
  strict bounded lengths and enumerated values.
- Rationale: All authorization-relevant behavior must be derivable from the
  persisted record itself rather than from implicit host expectations.
- Alternatives considered: Separate policy tables or host-maintained metadata
  were rejected because they create split-brain authorization and rollback risk.

## Anti-Rollback Evidence

- Decision: Use a monotonic store epoch plus per-record revision counters and
  integrity tags, and tie store acceptance to the device-managed persistent
  state rather than claiming hardware-enforced monotonic counters.
- Rationale: The RP2350 platform does not provide strong hardware monotonic
  storage guarantees. The design must therefore be honest: detect stale or
  inconsistent store state relative to the current device record and fail into a
  restricted recovery condition when evidence does not match.
- Alternatives considered: Claiming complete rollback prevention from firmware
  alone was rejected because it overstates the hardware trust boundary.

## Destructive Operations and Remnant Handling

- Decision: Represent revoke and destroy as explicit journaled lifecycle
  transitions, and require destroy to clear secret-bearing storage bytes in the
  new terminal record while making older invalidated records unusable.
- Rationale: On flash media, historical cells may still contain older data until
  erase cycles occur. The trustworthy property for v1 is that destroyed keys are
  no longer accepted or exposed, and that new writes clear active in-memory
  copies and overwrite current live slots deterministically.
- Alternatives considered: Treating deletion as immediate physical erasure of
  every historical copy was rejected because the hardware and flash layout do
  not support that guarantee without a more complex erase-compaction design.

## Full-Store Behavior

- Decision: Fail closed with an explicit capacity error when no writable slot is
  available, and require an authorized revoke/destroy/garbage-collection path
  before accepting new persistent keys.
- Rationale: Silent eviction is incompatible with HSM semantics. Capacity must
  be a visible administrative condition.
- Alternatives considered: LRU eviction or opportunistic overwrite was rejected
  because it could silently discard still-authorized keys.

## Test and Verification Strategy

- Decision: Keep record encoding, boot reconstruction, lifecycle enforcement,
  and rollback/corruption handling testable in the `protocol` crate, then use
  the host probe for public command/status validation on hardware.
- Rationale: Most correctness risk is in deterministic record handling rather
  than HAL calls, so host-side tests should carry the majority of coverage.
- Alternatives considered: Hardware-first validation was rejected because it is
  slower, harder to reproduce, and weaker for malformed record vectors and edge
  cases.
