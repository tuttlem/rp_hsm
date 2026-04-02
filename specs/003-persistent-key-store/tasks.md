# Tasks: Persistent Key Store

**Input**: Design documents from `/specs/003-persistent-key-store/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, and misuse-case tests are REQUIRED for this feature because it changes key handling, persistence format, authorization behavior, and recovery logic.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this belongs to (e.g. `[US1]`, `[US2]`, `[US3]`)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Prepare the workspace and feature contracts for persistent key-store work.

- [X] T001 Update persistent key-store planning notes and command inventory in /home/michael/src/embedded/rp_hsm/specs/003-persistent-key-store/contracts/key-store-commands.md and /home/michael/src/embedded/rp_hsm/specs/003-persistent-key-store/contracts/key-store-records.md
- [X] T002 [P] Add persistent key-store command placeholders, lifecycle enums, and visibility rules in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T003 [P] Add key-store test module scaffolding in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [X] T004 [P] Extend the host probe scaffold for key-store status and management paths in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Build the shared key-store data model, persistence journal, and fail-safe validation paths required by every story.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T005 Define key-store state enums, record header types, lifecycle states, and store-status types in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T006 [P] Define `KeyStoreRecord`, `KeyMetadata`, `KeyMaterialEnvelope`, `PersistentKey`, `KeyStoreDirectory`, and `FreshnessAnchor` models in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T007 [P] Define fixed-capacity storage bounds, slot constants, and secret-buffer zeroization helpers in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T008 [P] Add key-store status, metadata, record-result, and destruction-result codecs in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T009 [P] Add bounded key-store request parsing and replay-sensitive payload validation in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T010 Implement append-only journal reconstruction, latest-record selection, and ambiguous-record detection in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T011 Implement freshness-anchor validation, rollback detection, and store readiness gating in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T012 Implement shared key-store authorization, state gating, and command-profile enforcement in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T013 Wire key-store types and helpers into /home/michael/src/embedded/rp_hsm/protocol/src/protocol/mod.rs and /home/michael/src/embedded/rp_hsm/protocol/src/lib.rs
- [X] T014 Integrate key-store initialization, boot-time scan, and readiness tracking into /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T015 [P] Add shared fixtures for key-store records, anchors, and bounded secret payloads in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/key_store_fixtures.rs

**Checkpoint**: Foundation ready. Durable-key, lifecycle, and recovery behavior can now be implemented independently.

---

## Phase 3: User Story 1 - Durable Key Retention (Priority: P1) 🎯 MVP

**Goal**: Persist allowed keys and their metadata across restart without partial-key exposure or silent data loss.

**Independent Test**: Create or import a persistent key, reboot or reconstruct the store, and confirm the key remains present with the same metadata and readiness state. Simulated interrupted writes must leave the store in a safe, non-usable state rather than creating a partial live key.

### Tests for User Story 1 ⚠️

- [X] T016 [P] [US1] Add contract tests for `GetKeyStoreStatus`, `PutPersistentKey`, `ListPersistentKeys`, and `GetKeyMetadata` in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/key_store_vectors.rs
- [X] T017 [P] [US1] Add durable-create and reboot-reconstruction tests in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/persistent_retention.rs
- [X] T018 [P] [US1] Add interrupted-write and partial-record rejection tests in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/journal_recovery.rs

### Implementation for User Story 1

- [X] T019 [P] [US1] Implement `GetKeyStoreStatus` state projection and readiness reporting in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T020 [P] [US1] Implement `PutPersistentKey` staging, metadata validation, and append-only record commit in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T021 [US1] Implement `ListPersistentKeys` and `GetKeyMetadata` non-secret projections in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T022 [US1] Register durable key-store commands, payload bounds, and source-state restrictions in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T023 [US1] Expose key-store status and durable-key responses through the firmware transport in /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T024 [US1] Extend the host probe with empty-store, durable-create, reboot-status, and metadata verification flows in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs
- [X] T025 [US1] Zeroize staged import buffers and temporary record-assembly storage after commit or rejection in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs

**Checkpoint**: User Story 1 is independently functional and testable.

---

## Phase 4: User Story 2 - Enforced Key Lifecycle Rules (Priority: P2)

**Goal**: Enforce explicit lifecycle and policy attributes so revoked, destroyed, or non-exportable keys cannot be used outside their declared rules.

**Independent Test**: Revoke and destroy persistent keys, then attempt later metadata, use, export, and repeated destructive operations to confirm deterministic denial or documented administrative visibility.

### Tests for User Story 2 ⚠️

- [X] T026 [P] [US2] Add contract tests for `RevokePersistentKey` and `DestroyPersistentKey` responses in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/key_lifecycle_vectors.rs
- [X] T027 [P] [US2] Add revoke, destroy, repeated-operation, and non-exportable-policy tests in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/key_lifecycle.rs
- [X] T028 [P] [US2] Add denied-use and denied-modification tests for revoked, pending-destroy, and destroyed keys in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/key_policy_enforcement.rs

### Implementation for User Story 2

- [X] T029 [P] [US2] Implement key lifecycle transitions for `active`, `revoked`, `pending_destroy`, and `destroyed` in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T030 [P] [US2] Implement `RevokePersistentKey` and `DestroyPersistentKey` journaling, terminal flags, and idempotent denial behavior in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T031 [US2] Implement policy enforcement helpers for usage masks, export policy, and lifecycle-gated denial in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T032 [US2] Register lifecycle-management command contracts and replay-sensitive handling in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T033 [US2] Update firmware key-store integration so lifecycle state changes and destruction outcomes are surfaced safely in /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T034 [US2] Extend the host probe with revoke, destroy, repeated-destroy, and post-destruction visibility checks in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs
- [X] T035 [US2] Clear live material bytes, staged destruction buffers, and non-secret projections that would otherwise expose secret remnants in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs

**Checkpoint**: User Stories 1 and 2 both work independently and lifecycle policy is reviewable.

---

## Phase 5: User Story 3 - Safe Storage Recovery (Priority: P3)

**Goal**: Detect corruption, rollback, torn writes, and inconsistent persisted state, then fail closed into a defined recovery-required condition instead of silently trusting stale or malformed records.

**Independent Test**: Present stale anchors, corrupted records, duplicate highest revisions, and full-store conditions and confirm the store rejects normal use while reporting bounded recovery-safe status.

### Tests for User Story 3 ⚠️

- [X] T036 [P] [US3] Add contract tests for degraded, full, and recovery-required `GetKeyStoreStatus` vectors in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/key_store_recovery_vectors.rs
- [X] T037 [P] [US3] Add corruption, duplicate-revision, and torn-write boot-scan tests in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/store_corruption.rs
- [X] T038 [P] [US3] Add rollback-anchor and stale-epoch detection tests in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/rollback_detection.rs
- [X] T039 [P] [US3] Add full-store capacity and no-implicit-eviction tests in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/store_capacity.rs

### Implementation for User Story 3

- [X] T040 [P] [US3] Implement degraded and recovery-required store outcomes for malformed, stale, or ambiguous records in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T041 [P] [US3] Implement full-store detection, explicit capacity errors, and slot-availability accounting in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T042 [US3] Implement boot-time rollback checks that bind store acceptance to the freshness anchor and device revision in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T043 [US3] Register recovery-safe key-store status behavior and deny normal key-management commands when the store is non-ready in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T044 [US3] Integrate corrupted-store, rollback-detected, and full-store boot behavior into /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T045 [US3] Extend the host probe with degraded-status, rollback-detected, and capacity-failure verification flows in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs
- [X] T046 [US3] Ensure rollback and corruption status paths never expose stale key bytes, stale metadata payloads, or undecodable record contents in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs

**Checkpoint**: All user stories are independently functional and fail-safe recovery is explicit.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Finish cross-story hardening, documentation, and end-to-end verification.

- [X] T047 [P] Update persistent key-store quickstart flows to match the implemented command surface in /home/michael/src/embedded/rp_hsm/specs/003-persistent-key-store/quickstart.md
- [X] T048 [P] Update key-store command and record contracts to match final implementation details in /home/michael/src/embedded/rp_hsm/specs/003-persistent-key-store/contracts/key-store-commands.md and /home/michael/src/embedded/rp_hsm/specs/003-persistent-key-store/contracts/key-store-records.md
- [X] T049 Run host-side protocol and contract tests for persistent key-store behavior in /home/michael/src/embedded/rp_hsm/protocol/tests
- [X] T050 Run firmware build and host probe validation for persistent key-store behavior from /home/michael/src/embedded/rp_hsm/README.md
- [X] T051 [P] Document persistent key-store cargo workflows, status expectations, and operator notes in /home/michael/src/embedded/rp_hsm/README.md

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies; can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion; blocks all user stories
- **User Story 1 (Phase 3)**: Depends on Foundational completion
- **User Story 2 (Phase 4)**: Depends on Foundational completion and reuses persistent-record machinery from US1, but remains independently testable
- **User Story 3 (Phase 5)**: Depends on Foundational completion and reuses journal and lifecycle behavior from earlier phases
- **Polish (Phase 6)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: First deliverable and MVP
- **User Story 2 (P2)**: Builds on the persistent-record model from Phase 2 and durable key creation from US1
- **User Story 3 (P3)**: Builds on the same record and lifecycle machinery, but remains independently testable through corruption and rollback fixtures

### Within Each User Story

- Required security and misuse-case tests must be written before implementation
- Data and record models before command registration
- Command registration before firmware and host-tool integration
- Secret-remnant clearing and fail-safe denial before story completion

### Parallel Opportunities

- Setup tasks `T002-T004` can run in parallel
- Foundational tasks `T006-T009` and `T015` can run in parallel after `T005`
- US1 tests `T016-T018` can run in parallel; implementation pair `T019-T020` can run in parallel
- US2 tests `T026-T028` can run in parallel; implementation pair `T029-T030` can run in parallel
- US3 tests `T036-T039` can run in parallel; implementation pair `T040-T041` can run in parallel
- Polish tasks `T047-T048` and `T051` can run in parallel

---

## Parallel Example: User Story 1

```bash
# Launch all User Story 1 tests together:
Task: "Add contract tests for GetKeyStoreStatus, PutPersistentKey, ListPersistentKeys, and GetKeyMetadata in protocol/tests/contract/key_store_vectors.rs"
Task: "Add durable-create and reboot-reconstruction tests in protocol/tests/protocol/persistent_retention.rs"
Task: "Add interrupted-write and partial-record rejection tests in protocol/tests/protocol/journal_recovery.rs"

# Launch independent implementation tasks together:
Task: "Implement GetKeyStoreStatus state projection and readiness reporting in protocol/src/protocol/state.rs"
Task: "Implement PutPersistentKey staging, metadata validation, and append-only record commit in protocol/src/protocol/state.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. Stop and validate durable retention independently

### Incremental Delivery

1. Complete Setup and Foundational work
2. Deliver User Story 1 and validate durable retention across reboot
3. Deliver User Story 2 and validate revoke/destroy/policy denial behavior
4. Deliver User Story 3 and validate rollback, corruption, and capacity failure handling
5. Finish with documentation and end-to-end verification

### Parallel Team Strategy

1. One developer handles record layout, journal scan, and freshness-anchor logic
2. One developer handles command contracts, parser integration, and firmware wiring
3. One developer handles host probe and contract/integration test expansion
4. Coordinate at the end of each story phase before moving to the next

---

## Notes

- [P] tasks touch different files and can be parallelized safely
- `[US1]`, `[US2]`, and `[US3]` map directly to the spec user stories
- Each story remains independently testable with explicit negative coverage
- Commit after each logical task group once tests pass
- Avoid widening command availability or exposing key material through status, logs, or test helpers
