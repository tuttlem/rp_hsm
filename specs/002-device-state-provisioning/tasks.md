# Tasks: Device State and Provisioning

**Input**: Design documents from `/specs/002-device-state-provisioning/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, and misuse-case tests are REQUIRED for this feature because it changes a trust boundary, command surface, persistence format, and authorization rules.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g. US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Prepare the workspace for lifecycle-state and provisioning development.

- [X] T001 Update feature command inventory and lifecycle planning notes in /home/michael/src/embedded/rp_hsm/specs/002-device-state-provisioning/contracts/provisioning-commands.md
- [X] T002 [P] Rename the `debug-console` build gate to `developer-mode` in /home/michael/src/embedded/rp_hsm/firmware/Cargo.toml, /home/michael/src/embedded/rp_hsm/firmware/src/main.rs, and /home/michael/src/embedded/rp_hsm/README.md
- [X] T003 [P] Add lifecycle command placeholders, developer-reset command IDs, and developer-mode visibility rules in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T004 [P] Add lifecycle probe and developer-reset scaffold for future state commands in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs
- [X] T005 [P] Add lifecycle test module stubs in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Build the shared lifecycle, persistence, and enforcement infrastructure required by every story.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T006 Define lifecycle state enums, transition metadata, authority roles, and developer-reset target semantics in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T007 [P] Define provisioning record, owner binding, transition intent, recovery policy, zeroize outcome, and developer-reset outcome models in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T008 [P] Add lifecycle status, provisioning, and developer-reset payload/response codecs in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T009 [P] Extend frame parsing and validation for lifecycle command payload bounds and developer-only command gating in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T010 Implement persisted-record integrity validation, pending-transition reconciliation, and fail-closed boot recovery helpers in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T011 Implement shared lifecycle command authorization, idempotency, replay enforcement, and developer-mode reachability checks in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T012 Wire lifecycle state handling and developer-mode configuration into the protocol engine public module surface in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/mod.rs and /home/michael/src/embedded/rp_hsm/protocol/src/lib.rs
- [X] T013 Integrate lifecycle status storage, developer-mode configuration, and protocol-engine initialization into /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T014 [P] Add shared fixtures and helpers for lifecycle record setup in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/lifecycle_fixtures.rs

**Checkpoint**: Foundation ready. User story implementation can now proceed in priority order.

---

## Phase 3: User Story 1 - Controlled Device Bring-Up (Priority: P1) 🎯 MVP

**Goal**: Move a device from factory or zeroized state through a bounded provisioning flow into operational state only after ownership bootstrap completes successfully.

**Independent Test**: Starting from a factory-state record, `BeginProvisioning` followed by `FinalizeProvisioning` moves the device to `operational`; malformed, repeated, or interrupted provisioning attempts leave it non-operational.

### Tests for User Story 1 ⚠️

- [X] T015 [P] [US1] Add contract tests for lifecycle status and provisioning command responses in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/provisioning_vectors.rs
- [X] T016 [P] [US1] Add misuse-case tests for malformed and repeated provisioning requests in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/provisioning_flow.rs
- [X] T017 [P] [US1] Add interrupted-transition and reconciliation tests for provisioning persistence in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/provisioning_recovery.rs

### Implementation for User Story 1

- [X] T018 [P] [US1] Implement `GetLifecycleStatus` request/response handling in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/mod.rs
- [X] T019 [P] [US1] Implement `BeginProvisioning` transition creation and owner-binding validation in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T020 [US1] Implement `FinalizeProvisioning` commit logic and provisioning-to-operational transition in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T021 [US1] Register provisioning commands, payload rules, and source-state restrictions in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T022 [US1] Expose provisioning lifecycle responses through the firmware developer-mode transport in /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T023 [US1] Extend the host probe with factory/provisioned/operational status checks in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs
- [X] T024 [US1] Ensure provisioning transition buffers and authorization snapshots are cleared after use in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs

**Checkpoint**: User Story 1 is independently functional and testable.

---

## Phase 4: User Story 2 - Predictable State Enforcement (Priority: P2)

**Goal**: Enforce the documented lifecycle state machine so only approved transitions and state-appropriate commands succeed.

**Independent Test**: Valid state changes succeed, invalid transitions fail deterministically, and routine commands stay unavailable in disallowed states such as `locked` or `provisioned`.

### Tests for User Story 2 ⚠️

- [X] T025 [P] [US2] Add state-transition denial tests for invalid source and target combinations in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/state_transitions.rs
- [X] T026 [P] [US2] Add contract tests for lock, unlock, and status-reporting behavior in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/state_enforcement_vectors.rs
- [X] T027 [P] [US2] Add protected-command gating tests for non-operational states in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/command_gating.rs

### Implementation for User Story 2

- [X] T028 [P] [US2] Implement `LockDevice` and `UnlockDevice` transitions in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T029 [P] [US2] Implement state-to-command profile mapping and operational command denial in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T030 [US2] Implement invalid-transition error reporting and deterministic denial outcomes in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/mod.rs
- [X] T031 [US2] Update firmware lifecycle status reporting and state persistence checkpoints in /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T032 [US2] Extend the host probe with lock/unlock and denied-transition checks in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs
- [X] T033 [US2] Ensure state-denial paths do not expose owner metadata or recovery context in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/mod.rs

**Checkpoint**: User Stories 1 and 2 both work independently and state enforcement is reviewable.

---

## Phase 5: User Story 3 - Safe Recovery and Destruction (Priority: P3)

**Goal**: Provide explicit recovery, recovery reactivation, zeroize, and developer-only reset flows that never bypass ownership controls and always end in a defined safe state.

**Independent Test**: Recovery enters a restricted mode without restoring routine operations, recovered devices require a dedicated reactivation command to return to `operational`, zeroize clears owner-bound state and ends in `zeroized` even after reboot, and developer reset is reachable only in `developer-mode` images and returns the device to the documented non-owned reset target.

### Tests for User Story 3 ⚠️

- [X] T034 [P] [US3] Add recovery-entry, recovery-exit, and explicit reactivation tests in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/recovery_flow.rs
- [X] T035 [P] [US3] Add zeroize completion, repeated-zeroize, and post-reboot tests in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/zeroize_flow.rs
- [X] T036 [P] [US3] Add developer-reset reachability and production-exclusion tests in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/developer_reset.rs
- [X] T037 [P] [US3] Add contract tests for recovery, recovery reactivation, zeroize, and developer-reset responses in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/recovery_zeroize_vectors.rs

### Implementation for User Story 3

- [X] T038 [P] [US3] Implement `EnterRecovery`, `RecoverToProvisioned`, and `ReactivateRecoveredProvisioning` transitions in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T039 [P] [US3] Implement `ExecuteZeroize` state changes, outcome flags, and owner-binding clearing in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T040 [P] [US3] Implement developer-only lifecycle reset that clears state and returns to the lab reset target in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T041 [US3] Implement reboot-time pending-transition reconciliation into recovery-safe outcomes in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T042 [US3] Register recovery, recovery reactivation, zeroize, and developer-reset command contracts and authority requirements in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T043 [US3] Integrate recovery-required, zeroized, and developer-reset boot behavior in /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T044 [US3] Extend the host probe with recovery reactivation, zeroize, and developer-reset verification flows in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs
- [X] T045 [US3] Zeroize transient recovery, destructive-action, and developer-reset authorization buffers in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs

**Checkpoint**: All user stories are independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Finish cross-story hardening, documentation, and verification.

- [X] T046 [P] Update lifecycle quickstart steps to match the implemented command surface in /home/michael/src/embedded/rp_hsm/specs/002-device-state-provisioning/quickstart.md
- [X] T047 [P] Update command and state contracts to reflect the final implementation details in /home/michael/src/embedded/rp_hsm/specs/002-device-state-provisioning/contracts/state-machine.md and /home/michael/src/embedded/rp_hsm/specs/002-device-state-provisioning/contracts/provisioning-commands.md
- [X] T048 Run host-side protocol and contract tests for lifecycle behavior in /home/michael/src/embedded/rp_hsm/protocol/tests
- [X] T049 Run firmware build and host probe validation for lifecycle behavior from /home/michael/src/embedded/rp_hsm/README.md
- [X] T050 [P] Document lifecycle, developer-mode, and probe cargo workflows in /home/michael/src/embedded/rp_hsm/README.md

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies; can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion; blocks all user stories
- **User Story 1 (Phase 3)**: Depends on Foundational completion
- **User Story 2 (Phase 4)**: Depends on Foundational completion and reuses lifecycle entities from US1, but remains independently testable
- **User Story 3 (Phase 5)**: Depends on Foundational completion and reuses lifecycle persistence and command enforcement from earlier stories
- **Polish (Phase 6)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: First deliverable and MVP
- **User Story 2 (P2)**: Builds on the shared lifecycle model from Phase 2 and should be validated after US1
- **User Story 3 (P3)**: Builds on lifecycle persistence and explicit authority checks from US1 and US2

### Within Each User Story

- Required misuse-case and contract tests must be written before implementation
- Lifecycle entities and transition rules before command registration
- Command registration before firmware and host-tool integration
- Zeroization and denial-path cleanup before story completion

### Parallel Opportunities

- Setup tasks `T002-T005` can run in parallel
- Foundational tasks `T007-T009` and `T014` can run in parallel after `T006`
- US1 tests `T015-T017` can run in parallel; implementation pair `T018-T019` can run in parallel
- US2 tests `T025-T027` can run in parallel; implementation pair `T028-T029` can run in parallel
- US3 tests `T034-T037` can run in parallel; implementation trio `T038-T040` can run in parallel
- Polish tasks `T046-T047` and `T050` can run in parallel

---

## Parallel Example: User Story 1

```bash
# Launch all User Story 1 tests together:
Task: "Add contract tests for lifecycle status and provisioning command responses in protocol/tests/contract/provisioning_vectors.rs"
Task: "Add misuse-case tests for malformed and repeated provisioning requests in protocol/tests/protocol/provisioning_flow.rs"
Task: "Add interrupted-transition and reconciliation tests for provisioning persistence in protocol/tests/protocol/provisioning_recovery.rs"

# Launch independent implementation tasks together:
Task: "Implement GetLifecycleStatus request/response handling in protocol/src/protocol/mod.rs"
Task: "Implement BeginProvisioning transition creation and owner-binding validation in protocol/src/protocol/state.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. Stop and validate the provisioning bring-up flow independently

### Incremental Delivery

1. Complete Setup and Foundational work
2. Deliver User Story 1 and validate provisioning bring-up
3. Deliver User Story 2 and validate denied transitions plus lock/unlock behavior
4. Deliver User Story 3 and validate recovery and zeroize behavior
5. Finish with documentation and end-to-end verification

### Parallel Team Strategy

1. One developer handles lifecycle models and persistence helpers
2. One developer handles command contracts and protocol-engine wiring
3. One developer handles host probe and contract test expansion
4. Coordinate at the end of each story phase before moving to the next

---

## Notes

- [P] tasks touch different files and can be parallelized safely
- [US1], [US2], and [US3] map directly to the spec user stories
- Each story remains independently testable with explicit negative coverage
- Commit after each logical task group once tests pass
- Avoid widening command availability or leaking owner/recovery metadata during implementation
