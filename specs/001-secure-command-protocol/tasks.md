# Tasks: Secure Command Protocol

**Input**: Design documents from `/specs/001-secure-command-protocol/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, and misuse-case tests are REQUIRED for this
feature because it changes the external command surface and trust boundary
between host input and firmware state.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Single project**: `src/`, `tests/` at repository root
- Paths below use the embedded firmware structure defined in `plan.md`

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the protocol module layout and feature-level documentation scaffolding

- [X] T001 Create the protocol module skeleton in `/home/michael/src/embedded/rp_hsm/src/protocol/mod.rs`
- [X] T002 [P] Create the frame type scaffold in `/home/michael/src/embedded/rp_hsm/src/protocol/frame.rs`
- [X] T003 [P] Create the command metadata scaffold in `/home/michael/src/embedded/rp_hsm/src/protocol/command.rs`
- [X] T004 [P] Create the codec and parser scaffolds in `/home/michael/src/embedded/rp_hsm/src/protocol/codec.rs` and `/home/michael/src/embedded/rp_hsm/src/protocol/parser.rs`
- [X] T005 [P] Create the protocol state gating scaffold in `/home/michael/src/embedded/rp_hsm/src/protocol/state.rs`
- [X] T006 [P] Create protocol test directories and placeholder files in `/home/michael/src/embedded/rp_hsm/tests/protocol/frame_roundtrip.rs`, `/home/michael/src/embedded/rp_hsm/tests/protocol/malformed_input.rs`, `/home/michael/src/embedded/rp_hsm/tests/protocol/state_enforcement.rs`, and `/home/michael/src/embedded/rp_hsm/tests/contract/protocol_vectors.rs`
- [X] T007 [P] Capture feature threat assumptions and protocol limits in `/home/michael/src/embedded/rp_hsm/specs/001-secure-command-protocol/quickstart.md`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Build the shared protocol infrastructure that all user stories depend on

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T008 Define shared protocol constants, maximum frame sizes, and reserved field rules in `/home/michael/src/embedded/rp_hsm/src/protocol/frame.rs`
- [X] T009 [P] Define the core protocol data types for `ProtocolFrame`, `MessageKind`, and bounded payload handling in `/home/michael/src/embedded/rp_hsm/src/protocol/frame.rs`
- [X] T010 [P] Define command families, command IDs, replay policy, idempotency policy, and bootstrap command metadata in `/home/michael/src/embedded/rp_hsm/src/protocol/command.rs`
- [X] T011 [P] Define protocol status codes and denial categories in `/home/michael/src/embedded/rp_hsm/src/protocol/codec.rs`
- [X] T012 Implement parse pipeline stages and fail-safe parse outcomes in `/home/michael/src/embedded/rp_hsm/src/protocol/parser.rs`
- [X] T013 Implement device/session state gating primitives and reserved-family denial behavior in `/home/michael/src/embedded/rp_hsm/src/protocol/state.rs`
- [X] T014 Integrate the protocol module boundary into `/home/michael/src/embedded/rp_hsm/src/main.rs` without exposing debug-only protocol behavior
- [X] T015 Define buffer clearing and transient frame lifecycle handling in `/home/michael/src/embedded/rp_hsm/src/protocol/codec.rs`

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Safe Command Exchange (Priority: P1) 🎯 MVP

**Goal**: Deliver well-formed request/response handling for the initial bootstrap command set

**Independent Test**: Send valid `GetProtocolVersion`, `GetDeviceStatus`, and `GetCommandCatalog` requests and verify consistent framed responses and validation errors for incomplete payloads.

### Tests for User Story 1 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T016 [P] [US1] Add frame roundtrip tests for valid request and response serialization in `/home/michael/src/embedded/rp_hsm/tests/protocol/frame_roundtrip.rs`
- [X] T017 [P] [US1] Add bootstrap command contract vector tests for `GetProtocolVersion`, `GetDeviceStatus`, and `GetCommandCatalog` in `/home/michael/src/embedded/rp_hsm/tests/contract/protocol_vectors.rs`

### Implementation for User Story 1

- [X] T018 [P] [US1] Implement complete request/response frame encoding and decoding in `/home/michael/src/embedded/rp_hsm/src/protocol/codec.rs`
- [X] T019 [P] [US1] Implement bootstrap command definitions and response schemas in `/home/michael/src/embedded/rp_hsm/src/protocol/command.rs`
- [X] T020 [US1] Implement valid request parsing and bootstrap dispatch in `/home/michael/src/embedded/rp_hsm/src/protocol/parser.rs`
- [X] T021 [US1] Wire bootstrap protocol handling into the main firmware loop in `/home/michael/src/embedded/rp_hsm/src/main.rs`
- [X] T022 [US1] Add validation error handling for missing or incomplete bootstrap command payloads in `/home/michael/src/embedded/rp_hsm/src/protocol/parser.rs`
- [X] T023 [US1] Verify protocol handling does not expose secrets or privileged internal state through `/home/michael/src/embedded/rp_hsm/src/logging.rs` and `/home/michael/src/embedded/rp_hsm/src/main.rs`

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Safe Rejection of Invalid Traffic (Priority: P2)

**Goal**: Reject malformed, truncated, oversized, replay-sensitive, and unsupported requests deterministically

**Independent Test**: Submit malformed and unsupported frames and confirm that each case yields a defined denial outcome without partial command execution or protected state change.

### Tests for User Story 2 ⚠️

- [X] T024 [P] [US2] Add malformed-input denial tests for invalid length, oversized payload, reserved flag misuse, and truncation in `/home/michael/src/embedded/rp_hsm/tests/protocol/malformed_input.rs`
- [X] T025 [P] [US2] Add contract tests for unknown-version and unknown-command denial outcomes in `/home/michael/src/embedded/rp_hsm/tests/contract/protocol_vectors.rs`

### Implementation for User Story 2

- [X] T026 [P] [US2] Implement structural frame validation and malformed-input denial mapping in `/home/michael/src/embedded/rp_hsm/src/protocol/parser.rs`
- [X] T027 [US2] Implement explicit unsupported-version and unknown-command denials in `/home/michael/src/embedded/rp_hsm/src/protocol/parser.rs`
- [X] T028 [US2] Implement replay-policy and duplicate-handling hooks for replay-sensitive command metadata in `/home/michael/src/embedded/rp_hsm/src/protocol/state.rs`
- [X] T029 [US2] Integrate denial outcomes with response serialization so invalid traffic never reaches command execution in `/home/michael/src/embedded/rp_hsm/src/protocol/codec.rs`

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Explicit Command Boundaries (Priority: P3)

**Goal**: Enforce command family visibility and state/authorization requirements explicitly

**Independent Test**: Attempt reserved-family and out-of-state commands and verify that command eligibility is determined only by documented device/session state rules.

### Tests for User Story 3 ⚠️

- [X] T030 [P] [US3] Add state-enforcement tests for out-of-state and unauthorized command denial in `/home/michael/src/embedded/rp_hsm/tests/protocol/state_enforcement.rs`
- [X] T031 [P] [US3] Add contract tests for reserved-family denial behavior and command catalog visibility in `/home/michael/src/embedded/rp_hsm/tests/contract/protocol_vectors.rs`

### Implementation for User Story 3

- [X] T032 [P] [US3] Implement command eligibility checks for device state and session state in `/home/michael/src/embedded/rp_hsm/src/protocol/state.rs`
- [X] T033 [US3] Implement reserved command family metadata and denial behavior in `/home/michael/src/embedded/rp_hsm/src/protocol/command.rs`
- [X] T034 [US3] Implement command catalog filtering and state-aware exposure rules in `/home/michael/src/embedded/rp_hsm/src/protocol/parser.rs`
- [X] T035 [US3] Integrate command-boundary enforcement into the main protocol entry path in `/home/michael/src/embedded/rp_hsm/src/main.rs`

**Checkpoint**: All user stories should now be independently functional

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Finish validation, documentation, and cross-story cleanup

- [X] T036 [P] Update protocol documentation to match implemented frame and command behavior in `/home/michael/src/embedded/rp_hsm/specs/001-secure-command-protocol/contracts/protocol-frame.md` and `/home/michael/src/embedded/rp_hsm/specs/001-secure-command-protocol/contracts/command-catalog.md`
- [X] T037 Refine protocol module comments, cleanup shared code paths, and remove dead scaffolding in `/home/michael/src/embedded/rp_hsm/src/protocol/mod.rs`, `/home/michael/src/embedded/rp_hsm/src/protocol/frame.rs`, `/home/michael/src/embedded/rp_hsm/src/protocol/command.rs`, `/home/michael/src/embedded/rp_hsm/src/protocol/codec.rs`, `/home/michael/src/embedded/rp_hsm/src/protocol/parser.rs`, and `/home/michael/src/embedded/rp_hsm/src/protocol/state.rs`
- [X] T038 [P] Add additional protocol unit coverage for shared denial paths in `/home/michael/src/embedded/rp_hsm/tests/protocol/frame_roundtrip.rs`, `/home/michael/src/embedded/rp_hsm/tests/protocol/malformed_input.rs`, and `/home/michael/src/embedded/rp_hsm/tests/protocol/state_enforcement.rs`
- [X] T039 Run quickstart validation and record any feature-level corrections in `/home/michael/src/embedded/rp_hsm/specs/001-secure-command-protocol/quickstart.md`
- [X] T040 Run project validation checks and address failures via `/home/michael/src/embedded/rp_hsm/Cargo.toml`, `/home/michael/src/embedded/rp_hsm/src/main.rs`, and `/home/michael/src/embedded/rp_hsm/src/protocol/`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel if staffed
  - Recommended execution remains sequential in priority order P1 → P2 → P3
- **Polish (Phase 6)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational completion - No dependencies on other stories
- **User Story 2 (P2)**: Depends on User Story 1 frame encode/decode and parser dispatch behavior being present
- **User Story 3 (P3)**: Depends on User Story 1 bootstrap catalog and User Story 2 denial mapping being present

### Within Each User Story

- Required security and misuse-case tests MUST be written and FAIL before implementation
- Shared frame and command models before parser behavior
- Parser behavior before main-loop integration
- Denial mapping before response serialization hardening
- Story complete before moving to next priority

### Parallel Opportunities

- T002-T007 can run in parallel after T001 establishes the module tree
- T009-T011 can run in parallel once T008 defines shared limits
- T016 and T017 can run in parallel
- T018 and T019 can run in parallel
- T024 and T025 can run in parallel
- T030 and T031 can run in parallel
- T036 and T038 can run in parallel during polish

---

## Parallel Example: User Story 1

```bash
# Launch User Story 1 tests together:
Task: "T016 [US1] Add frame roundtrip tests in /home/michael/src/embedded/rp_hsm/tests/protocol/frame_roundtrip.rs"
Task: "T017 [US1] Add bootstrap command contract vector tests in /home/michael/src/embedded/rp_hsm/tests/contract/protocol_vectors.rs"

# Launch User Story 1 implementation slices together:
Task: "T018 [US1] Implement frame encoding/decoding in /home/michael/src/embedded/rp_hsm/src/protocol/codec.rs"
Task: "T019 [US1] Implement bootstrap command definitions in /home/michael/src/embedded/rp_hsm/src/protocol/command.rs"
```

## Parallel Example: User Story 2

```bash
# Launch User Story 2 tests together:
Task: "T024 [US2] Add malformed-input denial tests in /home/michael/src/embedded/rp_hsm/tests/protocol/malformed_input.rs"
Task: "T025 [US2] Add unknown-version and unknown-command contract tests in /home/michael/src/embedded/rp_hsm/tests/contract/protocol_vectors.rs"

# Launch User Story 2 implementation slices together:
Task: "T026 [US2] Implement structural frame validation in /home/michael/src/embedded/rp_hsm/src/protocol/parser.rs"
Task: "T028 [US2] Implement replay-policy hooks in /home/michael/src/embedded/rp_hsm/src/protocol/state.rs"
```

## Parallel Example: User Story 3

```bash
# Launch User Story 3 tests together:
Task: "T030 [US3] Add state-enforcement tests in /home/michael/src/embedded/rp_hsm/tests/protocol/state_enforcement.rs"
Task: "T031 [US3] Add reserved-family contract tests in /home/michael/src/embedded/rp_hsm/tests/contract/protocol_vectors.rs"

# Launch User Story 3 implementation slices together:
Task: "T032 [US3] Implement command eligibility checks in /home/michael/src/embedded/rp_hsm/src/protocol/state.rs"
Task: "T033 [US3] Implement reserved family metadata in /home/michael/src/embedded/rp_hsm/src/protocol/command.rs"
```

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Run the bootstrap command tests and ensure valid request/response handling works end to end
5. Demo protocol framing and bootstrap discovery/status commands only

### Incremental Delivery

1. Complete Setup + Foundational → protocol core ready
2. Add User Story 1 → Validate safe command exchange
3. Add User Story 2 → Validate malformed and unsupported traffic denials
4. Add User Story 3 → Validate explicit command boundary enforcement
5. Finish Polish phase → align contracts, tests, and quickstart with shipped behavior

### Parallel Team Strategy

With multiple developers:

1. One developer completes protocol scaffolding and shared frame models
2. Once foundational work is done:
   - Developer A: User Story 1 bootstrap command flow
   - Developer B: User Story 2 malformed-input and denial behavior
   - Developer C: User Story 3 command-boundary enforcement
3. Rejoin for polish, contract alignment, and validation

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story is independently completable and testable once foundational work is done
- Required tests are listed before implementation tasks for every story
- Avoid widening the command surface beyond the bootstrap catalog in this feature
