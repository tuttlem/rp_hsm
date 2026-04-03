# Tasks: Audit Trail

**Input**: Design documents from `/specs/007-audit-trail/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, misuse-case, contract, retention, and hardware-probe tests are required for this feature because it changes persisted observability state, adds new command surfaces, and introduces privileged retrieval and redaction behavior at the device trust boundary.

**Organization**: Tasks are grouped by user story so each story can be implemented and tested independently.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (`US1`, `US2`, `US3`)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Capture the audit feature boundary and reserve validation/documentation surfaces.

- [X] T001 Capture the v1 audit-trail scope, event taxonomy, retrieval surface, and redaction boundary in /home/michael/src/embedded/rp_hsm/specs/007-audit-trail/contracts/
- [X] T002 [P] Add README notes for audit retrieval, health-status behavior, and developer-mode validation expectations in /home/michael/src/embedded/rp_hsm/README.md
- [X] T003 [P] Reserve protocol and contract test modules for audit, health, retention, and redaction scenarios in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [X] T004 [P] Reserve host validation sections for audit retrieval and health-status coverage in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared audit structures, persistence, and encoding support that must exist before any user story can be implemented.

**⚠️ CRITICAL**: No user story work should begin until this phase is complete.

- [X] T005 Define audit and observability command metadata, event/result enums, and role visibility rules in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T006 [P] Extend request and response codecs for `GetAuditPage`, `GetHealthStatus`, bounded audit-event detail payloads, and cursor fields in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T007 [P] Add `AuditEvent`, `AuditRecordSet`, `AuditRetrievalCursor`, `HealthStatusView`, and retention-policy state structures to /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T008 [P] Add bounded audit staging buffers, event redaction helpers, and temporary retrieval-page clearing helpers to /home/michael/src/embedded/rp_hsm/protocol/src/protocol/mod.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T009 Implement protocol-engine storage for audit sequence tracking, overflow counters, retrieval cursors, and corruption flags in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T010 [P] Extend flash persistence structures for audit journal pages, retention metadata, and audit-corruption markers in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs
- [X] T011 [P] Wire audit-journal restore, fail-closed ambiguity handling, and bounded audit-write hooks into /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T012 [P] Add foundational contract coverage for audit command encoding, page bounds, and health-status field redaction in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/audit_command_vectors.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract/health_status_vectors.rs
- [X] T013 [P] Add foundational protocol coverage for malformed retrieval requests, oversized page requests, and ambiguous audit persistence restore in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/audit_surface_validation.rs
- [X] T014 [P] Add client-side parsing support for audit pages, health-status responses, and audit-specific denial rendering in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/
- [X] T015 Document audit ordering guarantees, retention behavior, redaction limits, and developer-mode helper constraints in /home/michael/src/embedded/rp_hsm/specs/007-audit-trail/quickstart.md and /home/michael/src/embedded/rp_hsm/README.md

**Checkpoint**: Audit event structures, journal persistence, codec support, and validation scaffolding are ready for story work.

---

## Phase 3: User Story 1 - Review Security-Relevant Actions (Priority: P1) 🎯 MVP

**Goal**: Record and retrieve security-relevant administrative and denial events so an authorized reviewer can reconstruct what happened without debug firmware.

**Independent Test**: Perform representative privileged actions, denials, and lifecycle transitions, retrieve the resulting audit pages, and confirm the events are present, ordered, and understandable.

### Tests for User Story 1 ⚠️

- [X] T016 [P] [US1] Add protocol tests for recording privileged actions, policy denials, session invalidation, and lifecycle transitions into the audit journal in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/audit_event_capture.rs
- [X] T017 [P] [US1] Add protocol tests for paged audit retrieval ordering, cursor advancement, and bounded page sizes in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/audit_retrieval_flow.rs
- [X] T018 [P] [US1] Add contract tests for audit event taxonomy, event/result encoding, and page response shape in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/audit_event_vectors.rs
- [X] T019 [P] [US1] Add host probe assertions for representative audited actions and ordered page retrieval in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 1

- [X] T020 [P] [US1] Implement the audit event taxonomy, sequence assignment, and event detail truncation rules in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T021 [P] [US1] Implement append-only audit recording hooks for administrative actions, denials, and lifecycle transitions in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T022 [P] [US1] Implement paged `GetAuditPage` retrieval with retained-window checks and cursor advancement in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T023 [US1] Persist audit append operations, restart restore, and monotonic sequence continuity in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs and /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T024 [US1] Add audit-review client rendering, cursor output, and page formatting to /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T025 [US1] Add CLI support for authorized audit-page retrieval in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs, /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs, and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T026 [US1] Align audit command contracts, event taxonomy, and retrieval examples with the implemented MVP in /home/michael/src/embedded/rp_hsm/specs/007-audit-trail/contracts/audit-commands.md and /home/michael/src/embedded/rp_hsm/specs/007-audit-trail/contracts/event-taxonomy.md

**Checkpoint**: User Story 1 should now provide a usable, reviewable audit-trail MVP.

---

## Phase 4: User Story 2 - Safe Operational Visibility (Priority: P2)

**Goal**: Expose an approved health-status surface that helps operators diagnose device condition without exposing secrets or requiring debug firmware.

**Independent Test**: Request health status across normal, locked, recovery, and degraded conditions and confirm the output remains useful while omitting secrets and privileged internals.

### Tests for User Story 2 ⚠️

- [X] T027 [P] [US2] Add protocol tests for `GetHealthStatus` in normal, locked, recovery, zeroized, and degraded states in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/health_status_flow.rs
- [X] T028 [P] [US2] Add protocol misuse-case tests that assert health responses do not expose key material, auth proofs, approval secrets, or unrestricted internal buffers in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/health_redaction.rs
- [X] T029 [P] [US2] Add contract tests for role-scoped health visibility, field redaction, and bounded error semantics in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/health_status_vectors.rs
- [X] T030 [P] [US2] Add host probe assertions for health reporting across representative device conditions in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 2

- [X] T031 [P] [US2] Implement `HealthStatusView` composition from lifecycle, key-store, session, policy, and audit-store state in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T032 [P] [US2] Implement `GetHealthStatus` dispatch, role-scoped disclosure, and fail-closed health error handling in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T033 [US2] Add audit recording for health-status access and health-status denial events in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T034 [US2] Surface health status in the host client and user-facing CLI output in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs, /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs, and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T035 [US2] Align redaction, disclosure-level, and degraded-status documentation with the implementation in /home/michael/src/embedded/rp_hsm/specs/007-audit-trail/contracts/retention-and-redaction.md and /home/michael/src/embedded/rp_hsm/specs/007-audit-trail/quickstart.md

**Checkpoint**: User Stories 1 and 2 should now provide both audit review and safe operational visibility.

---

## Phase 5: User Story 3 - Controlled Retention and Disclosure (Priority: P3)

**Goal**: Enforce explicit retention, overwrite, authorization, and redaction rules so constrained audit storage remains reviewable without becoming a disclosure channel.

**Independent Test**: Fill the audit journal beyond capacity, retrieve retained pages through approved roles, attempt unauthorized retrieval, and confirm retention and disclosure rules are enforced exactly as documented.

### Tests for User Story 3 ⚠️

- [X] T036 [P] [US3] Add protocol tests for overwrite-oldest retention, overflow counting, and retained-window retrieval after capacity rollover in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/audit_retention_flow.rs
- [X] T037 [P] [US3] Add protocol misuse-case tests for unauthorized audit retrieval, oversized requests, and secret-bearing detail rejection in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/audit_disclosure_controls.rs
- [X] T038 [P] [US3] Add protocol tests for audit corruption, ambiguous restore, and retrieval lockout failing closed in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/audit_fail_closed.rs
- [X] T039 [P] [US3] Add contract tests for retention semantics, redaction rules, and retrieval-window behavior in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/audit_retention_vectors.rs
- [X] T040 [P] [US3] Add host probe and CLI regression checks for rollover, unauthorized retrieval denial, and degraded-audit status reporting in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs

### Implementation for User Story 3

- [X] T041 [P] [US3] Implement overwrite-oldest retention, overflow summaries, and retained-window tracking in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T042 [P] [US3] Implement audit retrieval authorization, retained-window denial classes, and retrieval-lock state transitions in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T043 [P] [US3] Implement fail-closed audit restore, corruption marking, and degraded observability behavior in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs and /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T044 [US3] Add developer-mode audit fault-injection and retention test helpers for live validation in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs, /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs, and /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs
- [X] T045 [US3] Add CLI rendering for audit overflow, retrieval truncation, and audit-corruption status in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T046 [US3] Align retention, redaction, and failure semantics with the implemented behavior in /home/michael/src/embedded/rp_hsm/specs/007-audit-trail/contracts/retention-and-redaction.md, /home/michael/src/embedded/rp_hsm/specs/007-audit-trail/contracts/audit-commands.md, and /home/michael/src/embedded/rp_hsm/specs/007-audit-trail/quickstart.md

**Checkpoint**: All user stories should now be independently functional and reviewable.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final integration, cleanup, and end-to-end validation across the audit and health surfaces.

- [X] T047 [P] Add end-to-end audit and health regression coverage across /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [X] T048 [P] Clean up duplicated observability/status code paths and migrate remaining audit-sensitive checks into centralized helpers in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T049 [P] Update operator workflow notes and `rphsmtool` help text for audit retrieval, health status, and developer-mode validation in /home/michael/src/embedded/rp_hsm/README.md and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T050 Run the audit quickstart validation sequence and align any drift in /home/michael/src/embedded/rp_hsm/specs/007-audit-trail/quickstart.md
- [X] T051 Run workspace validation commands and record completion status in /home/michael/src/embedded/rp_hsm/specs/007-audit-trail/tasks.md

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies, can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion and blocks all story work
- **User Story phases (Phases 3-5)**: Depend on Foundational completion
- **Polish (Phase 6)**: Depends on the desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Starts after Foundational completion and delivers the MVP audit trail
- **User Story 2 (P2)**: Starts after Foundational completion and depends on the shared audit and status structures from US1
- **User Story 3 (P3)**: Starts after Foundational completion and depends on the shared journal, retrieval, and redaction behavior from US1 and US2

### Within Each User Story

- Required tests must exist and fail before implementation is considered complete
- Command and codec support before host tooling
- Journal persistence before restart and retention validation
- Redaction helpers before health and retrieval output is considered complete
- Contract alignment before final quickstart sign-off

### Parallel Opportunities

- Setup tasks `T002-T004`
- Foundational tasks `T006-T008` and `T010-T014`
- US1 tests `T016-T019` and implementation trio `T020-T022`
- US2 tests `T027-T030` and implementation pair `T031-T032`
- US3 tests `T036-T040` and implementation trio `T041-T043`
- Polish tasks `T047-T049`

---

## Parallel Example: User Story 1

```bash
# Launch US1 validation tasks together:
Task: "Add protocol tests for recording privileged actions, policy denials, session invalidation, and lifecycle transitions into the audit journal in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/audit_event_capture.rs"
Task: "Add protocol tests for paged audit retrieval ordering, cursor advancement, and bounded page sizes in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/audit_retrieval_flow.rs"
Task: "Add host probe assertions for representative audited actions and ordered page retrieval in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs"

# Launch US1 implementation tasks together:
Task: "Implement the audit event taxonomy, sequence assignment, and event detail truncation rules in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs"
Task: "Implement append-only audit recording hooks for administrative actions, denials, and lifecycle transitions in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs"
Task: "Implement paged GetAuditPage retrieval with retained-window checks and cursor advancement in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. Validate audit capture and ordered retrieval independently before moving on

### Incremental Delivery

1. Setup + Foundational
2. User Story 1: audit event capture and retrieval
3. User Story 2: redacted health and safe visibility
4. User Story 3: retention, redaction, and fail-closed disclosure control
5. Polish and hardware validation

### Suggested MVP Scope

- Phase 1
- Phase 2
- Phase 3 only

---

## Notes

- [P] tasks are parallelizable because they touch separate files or independent validation surfaces
- Each user story remains independently testable against its own acceptance criteria
- Required misuse-case and malformed-input tests are included because this feature changes persisted observability and authorization behavior
