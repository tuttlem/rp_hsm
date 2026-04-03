# Tasks: Signed Firmware Update

**Input**: Design documents from `/specs/008-signed-firmware-update/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, and misuse-case tests are REQUIRED for this feature because it changes a trust boundary, persistence format, authorization rules, and boot/update behavior.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., [US1], [US2], [US3])
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Capture the feature boundary and reserve the update surfaces that later phases will fill in.

- [x] T001 Capture the signed-update scope, trust assumptions, and command contracts in /home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/contracts/
- [x] T002 [P] Add roadmap and README notes for signed update, rollback policy, and recovery separation from developer flashing in /home/michael/src/embedded/rp_hsm/README.md and /home/michael/src/embedded/rp_hsm/ROADMAP.md
- [x] T003 [P] Reserve protocol test modules for update authorization, version policy, and interrupted-update recovery in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [x] T004 [P] Reserve host validation coverage for firmware update and recovery workflows in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared update state, slot metadata, and persistence infrastructure that MUST exist before any user story can be implemented.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [x] T005 Define firmware-update command metadata, lifecycle gating, and protected-action classes in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [x] T006 [P] Extend protocol codecs for update manifest submission, chunk transfer, activation status, and recovery-status payloads in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [x] T007 [P] Add shared firmware-version, slot-state, manifest, and update-session entities to /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/mod.rs
- [x] T008 [P] Extend protocol-engine storage for accepted firmware state, staged transfer state, and recovery-required markers in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [x] T009 Add flash persistence structures for active/staged slot metadata, accepted-version floor, and update-session restore state in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs
- [x] T010 [P] Wire boot-time update-state restore, ambiguity detection, and recovery-required reconciliation into /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [x] T011 [P] Add foundational contract coverage for update payload bounds, status shapes, and version-order encoding in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/firmware_update_vectors.rs
- [x] T012 [P] Add foundational protocol coverage for malformed update requests, oversized chunks, and ambiguous restore handling in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/update_surface_validation.rs
- [x] T013 [P] Add host-side parsing for update status, slot metadata, and version tuples in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs
- [x] T014 Document update trust boundaries, developer flashing separation, and fail-safe reboot rules in /home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/quickstart.md and /home/michael/src/embedded/rp_hsm/README.md

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Authorized Firmware Change (Priority: P1) 🎯 MVP

**Goal**: Allow only authorized signed firmware packages to enter the staged update path.

**Independent Test**: Submit one valid signed manifest and one unauthorized or untrusted update request, confirming only the approved trusted update begins transfer.

### Tests for User Story 1 ⚠️

- [x] T015 [P] [US1] Add protocol tests for unauthorized update begin, invalid manifest signature, and denied transfer start in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/update_authorization_flow.rs
- [x] T016 [P] [US1] Add contract tests for signed-manifest request and response shapes in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/firmware_update_vectors.rs
- [x] T017 [P] [US1] Add host probe checks for approved vs denied update authorization paths in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 1

- [x] T018 [P] [US1] Implement signed-manifest validation and trust-anchor checks in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [x] T019 [P] [US1] Implement authenticated `BeginFirmwareUpdate`, `TransferFirmwareChunk`, and `AbortFirmwareUpdate` handlers in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [x] T020 [US1] Persist staged-transfer progress, inactive-slot chunk writes, and transfer abort invalidation in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs and /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [x] T021 [US1] Add audit/event recording for update begin, denied begin, chunk progress, and abort paths in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [x] T022 [US1] Add `rphsmtool` support for update begin, chunk transfer, and abort in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs, /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs, and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [x] T023 [US1] Align update authorization, trust, and bounded package rules with the implementation in /home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/contracts/firmware-update-commands.md and /home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/contracts/update-package-format.md

**Checkpoint**: User Story 1 should now provide an authenticated signed-update entry path and safe denial behavior

---

## Phase 4: User Story 2 - Protected Version Progression (Priority: P2)

**Goal**: Enforce explicit version ordering and rollback-floor rules before a new image can be activated.

**Independent Test**: Attempt updates with equal, lower, and higher firmware versions and confirm only the policy-allowed version progresses to activation.

### Tests for User Story 2 ⚠️

- [x] T024 [P] [US2] Add protocol tests for equal-version, lower-version, lower-epoch, and newer-version update attempts in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/update_version_policy.rs
- [x] T025 [P] [US2] Add contract tests for version tuple ordering and activation-result payloads in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/firmware_version_policy_vectors.rs
- [x] T026 [P] [US2] Add host probe checks for rollback denial and accepted-version advancement in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 2

- [x] T027 [P] [US2] Implement firmware-version comparison, accepted-version floor, and rollback denial classes in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [x] T028 [P] [US2] Implement `FinalizeFirmwareUpdate`, `ActivateFirmwareUpdate`, and update-status reporting in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [x] T029 [US2] Persist active-slot promotion, version-floor advancement, and activation metadata in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs
- [x] T030 [US2] Add `rphsmtool` support for finalize, activate, and update-status output in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs, /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs, and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [x] T031 [US2] Integrate update activation with policy approval requirements and audit recording in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [x] T032 [US2] Align version-progression and rollback-policy docs with the implemented behavior in /home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/contracts/version-and-recovery-policy.md and /home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/quickstart.md

**Checkpoint**: User Stories 1 and 2 should now provide trusted authorized update plus explicit version-policy enforcement

---

## Phase 5: User Story 3 - Safe Recovery from Failed Updates (Priority: P3)

**Goal**: Ensure interrupted or ambiguous updates leave the device in a defined trusted or recoverable state without booting untrusted firmware.

**Independent Test**: Interrupt staged updates at defined points, reboot, and confirm the device either preserves the last trusted image or enters authorized recovery without booting the staged image.

### Tests for User Story 3 ⚠️

- [x] T033 [P] [US3] Add protocol tests for interrupted transfer, ambiguous activation metadata, and failed validation restore in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/update_recovery_flow.rs
- [x] T034 [P] [US3] Add protocol misuse-case tests for stale approval, lost session authority, and recovery abuse during update recovery in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/update_recovery_denials.rs
- [x] T035 [P] [US3] Add contract tests for recovery-status payloads, recovery authorization, and fail-closed boot outcomes in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/update_recovery_vectors.rs
- [x] T036 [P] [US3] Add host probe coverage for interrupted update, reboot, and trusted recovery behavior in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 3

- [x] T037 [P] [US3] Implement boot reconciliation, staged-image invalidation, and `recovery-required` transitions in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [x] T038 [P] [US3] Implement `RecoverTrustedFirmware` and related recovery-status/reporting flows in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [x] T039 [US3] Persist interrupted-update markers, ambiguous-slot metadata detection, and recovery-clear semantics in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs and /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [x] T040 [US3] Add developer-mode update fault helpers for live interruption/recovery validation in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs, /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs, and /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs
- [x] T041 [US3] Add `rphsmtool` support for recovery-status and trusted recovery actions in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs, /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs, and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [x] T042 [US3] Align interrupted-update, trusted-recovery, and fail-safe boot documentation with the implementation in /home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/contracts/version-and-recovery-policy.md and /home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/quickstart.md

**Checkpoint**: All user stories should now provide a complete signed update and recovery path

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final integration, operator guidance, and end-to-end validation across the update surface.

- [x] T043 [P] Add end-to-end update and recovery regression coverage across /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [x] T044 [P] Clean up duplicated update-state and slot-selection helpers in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs, /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs, and /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs
- [x] T045 [P] Update operator workflow notes and `rphsmtool` help text for signed update, version denial, and recovery actions in /home/michael/src/embedded/rp_hsm/README.md and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [ ] T046 Run the signed-update quickstart validation sequence and align any drift in /home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/quickstart.md
- [x] T047 Run workspace validation commands and record completion status in /home/michael/src/embedded/rp_hsm/specs/008-signed-firmware-update/tasks.md

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phases 3-5)**: Depend on Foundational completion
- **Polish (Phase 6)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational - no dependencies on other user stories
- **User Story 2 (P2)**: Can start after Foundational and builds on shared update commands from US1, but remains independently testable through version-policy scenarios
- **User Story 3 (P3)**: Can start after Foundational and depends on staged-update and activation metadata introduced by US1/US2

### Within Each User Story

- Required security and misuse-case tests MUST be written and fail before implementation
- Shared entities and state helpers before command handlers
- Protocol handlers before firmware persistence wiring
- Host tooling after command shapes are stable
- Documentation alignment after implementation behavior is fixed

### Parallel Opportunities

- Setup tasks `T002-T004`
- Foundational tasks `T006-T008` and `T011-T013`
- US1 tests `T015-T017` and implementation pair `T018-T019`
- US2 tests `T024-T026` and implementation pair `T027-T028`
- US3 tests `T033-T036` and implementation pair `T037-T038`
- Polish tasks `T043-T045`

---

## Parallel Example: User Story 1

```bash
# Launch US1 update-entry tests together:
Task: "Add protocol tests for unauthorized update begin, invalid manifest signature, and denied transfer start in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/update_authorization_flow.rs"
Task: "Add contract tests for signed-manifest request and response shapes in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/firmware_update_vectors.rs"
Task: "Add host probe checks for approved vs denied update authorization paths in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs"

# Launch US1 implementation slices together:
Task: "Implement signed-manifest validation and trust-anchor checks in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs"
Task: "Implement authenticated BeginFirmwareUpdate, TransferFirmwareChunk, and AbortFirmwareUpdate handlers in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: confirm only authorized signed updates can enter the staged path

### Incremental Delivery

1. Setup + Foundational
2. User Story 1: signed authorized update entry
3. User Story 2: version/rollback enforcement and activation
4. User Story 3: interrupted-update recovery and fail-safe boot behavior
5. Polish: full quickstart and hardware validation

### Parallel Team Strategy

With multiple developers:

1. Complete Setup + Foundational together
2. Then split:
   - Developer A: US1 signed manifest and transfer flow
   - Developer B: US2 version floor and activation rules
   - Developer C: US3 recovery and interruption handling

---

## Notes

- [P] tasks = different files, no dependencies
- [US#] labels map tasks to the corresponding user stories
- Each user story is independently testable
- Commit after each task or logical task group
- Stop at each checkpoint to validate behavior before widening the trust boundary
