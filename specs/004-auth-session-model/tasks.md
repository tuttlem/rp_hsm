# Tasks: Authentication and Session Model

**Input**: Design documents from `/specs/004-auth-session-model/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, and misuse-case tests are REQUIRED for this feature because it changes the authorization boundary, privileged command rules, and secret-handling paths.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Prepare the workspace and feature documentation for authentication and session work.

- [X] T001 Capture authentication command ids, role mappings, and session-policy notes in /home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/contracts/
- [X] T002 [P] Add README command notes for future auth/session probe coverage in /home/michael/src/embedded/rp_hsm/README.md
- [X] T003 [P] Reserve protocol test modules for auth/session scenarios in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [X] T004 [P] Reserve host probe sections for auth/session verification in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Build the shared auth/session primitives that every story depends on.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T005 Define auth/session command ids, role-aware command metadata, and catalog visibility in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T006 [P] Extend frame and payload codecs for authentication, session status, and session invalidation messages in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T007 [P] Add credential, challenge, session, replay, and failure-accounting data structures to /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T008 [P] Add bounded secret-clearing helpers and auth-specific validation markers to /home/michael/src/embedded/rp_hsm/protocol/src/protocol/mod.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T009 Implement protocol-engine storage for auth/session state, boot-time invalidation, and firmware-action plumbing in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T010 [P] Extend persisted snapshot structures for credential policy and lockout baselines in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs
- [X] T011 [P] Wire auth/session snapshot restore and reset behavior into /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T012 [P] Add foundational malformed-input and redaction regression coverage for the new auth/session codecs in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/auth_command_vectors.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract/auth_redaction_vectors.rs
- [X] T013 [P] Add foundational command-gating and role-mapping regression coverage in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/auth_administrative_access.rs
- [X] T014 Document developer-mode exclusions and production-build expectations for auth/session features in /home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/quickstart.md and /home/michael/src/embedded/rp_hsm/README.md

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Controlled Administrative Access (Priority: P1) 🎯 MVP

**Goal**: Require explicit authenticated session establishment before privileged commands can run, and grant only the reviewed role scope.

**Independent Test**: Attempt privileged commands before and after successful authentication and confirm that only authenticated sessions gain the declared administrative access.

### Tests for User Story 1 ⚠️

- [X] T015 [P] [US1] Add denial-first tests for unauthenticated privileged commands in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/auth_administrative_access.rs
- [X] T016 [P] [US1] Add contract tests for `BeginAuthentication`, `CompleteAuthentication`, `GetSessionStatus`, and `InvalidateSession` in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/auth_command_vectors.rs
- [X] T017 [P] [US1] Add host probe assertions for successful authentication and insufficient-role denial in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 1

- [X] T018 [P] [US1] Implement credential-record and role-policy behavior in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T019 [P] [US1] Implement challenge issuance and session activation payload handling in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T020 [US1] Implement `BeginAuthentication` and `CompleteAuthentication` dispatch paths in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T021 [US1] Enforce role-to-command authorization checks for lifecycle and key-store commands in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T022 [US1] Implement `GetSessionStatus` and `InvalidateSession` behavior in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T023 [US1] Persist reviewed credential policy and restore it safely on boot in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs and /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T024 [US1] Extend the developer-mode host probe to validate unauthenticated denial, successful authentication, and wrong-role denial on hardware in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs
- [X] T025 [US1] Update auth/session usage notes and command expectations in /home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/contracts/authentication-commands.md and /home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/quickstart.md

**Checkpoint**: User Story 1 should now provide explicit authenticated access control and role-scoped privileged execution.

---

## Phase 4: User Story 2 - Predictable Session Boundaries (Priority: P2)

**Goal**: Make session start, expiry, explicit invalidation, and lifecycle-driven invalidation deterministic and observable.

**Independent Test**: Establish sessions, allow them to expire, invalidate them manually, and verify that command access changes exactly as documented.

### Tests for User Story 2 ⚠️

- [X] T026 [P] [US2] Add protocol tests for session timeout, inactivity expiry, and explicit invalidation in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/session_boundaries.rs
- [X] T027 [P] [US2] Add protocol tests for reboot, zeroize, and lifecycle-driven session invalidation in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/session_invalidation.rs
- [X] T028 [P] [US2] Add host probe steps for expiry and logout validation in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 2

- [X] T029 [P] [US2] Implement session lifetime, inactivity tracking, and invalidation state transitions in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T030 [P] [US2] Add timeout and invalidation-aware status encoding in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T031 [US2] Enforce expiry and invalidation checks on every privileged request path in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T032 [US2] Invalidate sessions on reboot, zeroize, developer reset, recovery entry, and incompatible lifecycle change in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T033 [US2] Ensure boot restore clears active authenticated sessions while preserving reviewed credential policy in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs and /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T034 [US2] Extend hardware probe coverage for expiry, explicit invalidation, and reboot-driven invalidation in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs
- [X] T035 [US2] Update session-boundary contract details and examples in /home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/contracts/session-policy.md and /home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/quickstart.md

**Checkpoint**: User Stories 1 and 2 should now work independently with deterministic session termination semantics.

---

## Phase 5: User Story 3 - Abuse Resistance for Access Attempts (Priority: P3)

**Goal**: Deny brute-force and replay behavior with bounded lockout, freshness counters, and fail-safe denial of stale or duplicated privileged material.

**Independent Test**: Submit repeated failed authentication attempts, replay old requests, and send stale session material to confirm that the device enforces rate limits and freshness rules without granting access.

### Tests for User Story 3 ⚠️

- [X] T036 [P] [US3] Add protocol tests for repeated failed authentication attempts and lockout behavior in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/auth_lockout.rs
- [X] T037 [P] [US3] Add protocol tests for replayed and stale privileged request counters in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/session_freshness.rs
- [X] T038 [P] [US3] Add contract tests for redaction of denials and session status in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/auth_redaction_vectors.rs
- [X] T039 [P] [US3] Add host probe checks for lockout threshold behavior and replay denial in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 3

- [X] T040 [P] [US3] Implement failure-counter, backoff, and lockout policy handling in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T041 [P] [US3] Implement per-session request-counter freshness and bounded replay tracking in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T042 [US3] Enforce lockout denial and stale-proof handling in `BeginAuthentication` and `CompleteAuthentication` paths in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T043 [US3] Enforce session-id and request-counter freshness on privileged command dispatch in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T044 [US3] Persist reviewed lockout baseline and clear transient replay artifacts safely on reboot in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs and /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T045 [US3] Redact auth/session errors, logs, and status responses so they never expose reusable secret material in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs and /home/michael/src/embedded/rp_hsm/firmware/src/logging.rs
- [X] T046 [US3] Extend the hardware probe to validate failed-attempt thresholds, replay denial, and redacted responses in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs
- [X] T047 [US3] Update abuse-resistance and replay expectations in /home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/contracts/authentication-commands.md, /home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/contracts/session-policy.md, and /home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/quickstart.md

**Checkpoint**: All user stories should now be independently functional and security-testable.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final hardening, documentation alignment, and whole-feature validation.

- [X] T048 [P] Add end-to-end auth/session regression coverage across protocol suites in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [X] T049 [P] Clean up auth/session helper boundaries and dead code in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs, /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs, and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T050 Update hardware probe documentation and operator workflow for auth/session validation in /home/michael/src/embedded/rp_hsm/README.md
- [X] T051 Run the quickstart validation sequence and align any drift in /home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/quickstart.md
- [X] T052 Run workspace validation commands and record completion status in /home/michael/src/embedded/rp_hsm/specs/004-auth-session-model/tasks.md

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies, can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion and blocks all story work
- **User Story 1 (Phase 3)**: Depends on Foundational completion
- **User Story 2 (Phase 4)**: Depends on Foundational completion and integrates with US1 session primitives
- **User Story 3 (Phase 5)**: Depends on Foundational completion and builds on active-session semantics from US1 and invalidation logic from US2
- **Polish (Phase 6)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational, no dependency on other stories
- **User Story 2 (P2)**: Depends on the session establishment primitives from US1 but remains independently testable once those exist
- **User Story 3 (P3)**: Depends on authenticated-session behavior from US1 and session lifecycle behavior from US2

### Within Each User Story

- Required security and misuse-case tests must be written before implementation tasks for that story
- Data structures before parser dispatch
- Parser enforcement before firmware persistence integration
- Core implementation before host probe extension
- Story documentation and quickstart updates after behavior is stable

### Parallel Opportunities

- Setup tasks `T002-T004` can run in parallel
- Foundational tasks `T006-T008` and `T010-T013` can run in parallel
- US1 tests `T015-T017` can run in parallel, as can implementation pair `T018-T019`
- US2 tests `T026-T028` can run in parallel, as can implementation pair `T029-T030`
- US3 tests `T036-T039` can run in parallel, as can implementation pair `T040-T041`
- Polish tasks `T048-T049` can run in parallel

---

## Parallel Example: User Story 1

```bash
# Launch US1 auth boundary tests together:
Task: "Add denial-first tests for unauthenticated privileged commands in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/auth_administrative_access.rs"
Task: "Add contract tests for BeginAuthentication, CompleteAuthentication, GetSessionStatus, and InvalidateSession in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/auth_command_vectors.rs"

# Launch US1 auth data-path work together:
Task: "Implement credential-record and role-policy behavior in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs"
Task: "Implement challenge issuance and session activation payload handling in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. Stop and validate unauthenticated denial, successful authentication, and wrong-role denial

### Incremental Delivery

1. Setup + Foundational establish the shared auth/session substrate
2. Add US1 for explicit authenticated command control
3. Add US2 for expiry and invalidation semantics
4. Add US3 for lockout and replay resistance
5. Finish with cross-cutting documentation and full validation

### Parallel Team Strategy

1. Complete Setup + Foundational together
2. Once Foundational is done:
   - Developer A: US1 command/auth flow
   - Developer B: US2 expiry/invalidation behavior
   - Developer C: US3 lockout/replay enforcement
3. Integrate through the shared protocol tests and host probe

---

## Notes

- [P] tasks touch different files and can proceed without depending on incomplete tasks
- [US#] labels map every story task back to the spec for traceability
- Each user story is independently testable once its phase completes
- Required negative and misuse-case tests should fail before implementation begins
- Avoid widening the public command surface beyond the reviewed auth/session commands
