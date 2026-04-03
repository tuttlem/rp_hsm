# Tasks: Policy Enforcement

**Input**: Design documents from `/specs/006-policy-enforcement/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, misuse-case, contract, and hardware-probe tests are required for this feature because it changes authorization rules, destructive-action controls, persisted approval state, and denial behavior at the device trust boundary.

**Organization**: Tasks are grouped by user story so each story can be implemented and tested independently.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (`US1`, `US2`, `US3`)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Capture the policy feature boundary and reserve the validation surfaces.

- [X] T001 Capture the v1 policy-enforcement scope, protected-action set, and denial-class coverage in /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/contracts/
- [X] T002 [P] Add README notes for policy validation, approval workflows, and developer-mode probe expectations in /home/michael/src/embedded/rp_hsm/README.md
- [X] T003 [P] Reserve protocol and contract test modules for policy-matrix and approval scenarios in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [X] T004 [P] Reserve host validation sections for policy and approval coverage in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared policy infrastructure that must exist before any user story can be implemented.

**⚠️ CRITICAL**: No user story work should begin until this phase is complete.

- [X] T005 Define policy decision enums, approval classes, and command-policy metadata in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T006 [P] Extend request and response codecs for approval-ticket identifiers, bounded denial classes, and policy-status payloads in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T007 [P] Add `PolicyProfile`, `PolicyRule`, `ApprovalTicket`, `PolicyDecision`, and key-policy context structures to /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T008 [P] Add bounded approval-ticket storage, secret-bearing approval clearing helpers, and policy-evaluation ordering markers to /home/michael/src/embedded/rp_hsm/protocol/src/protocol/mod.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T009 Implement protocol-engine storage for active policy profile, approval ticket state, and denial bookkeeping in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T010 [P] Extend flash persistence structures for policy profile and approval-ticket snapshots in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs
- [X] T011 [P] Wire policy-profile restore, approval snapshot restore, and fail-closed ambiguity handling into /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T012 [P] Add foundational contract coverage for policy command coverage, denial classes, and approval-ticket bounds in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/policy_command_vectors.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract/policy_denial_vectors.rs
- [X] T013 [P] Add foundational protocol coverage for malformed policy inputs, duplicate-rule ambiguity, and missing-key-context denial in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/policy_surface_validation.rs
- [X] T014 [P] Add client-side parsing support for policy denial classes and approval responses in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/
- [X] T015 Document policy evaluation order, approval persistence, and production-vs-developer behavior in /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/quickstart.md and /home/michael/src/embedded/rp_hsm/README.md

**Checkpoint**: Policy profile, approval-ticket persistence, and test scaffolding are ready for story work.

---

## Phase 3: User Story 1 - Enforced Command Policy (Priority: P1) 🎯 MVP

**Goal**: Enforce an explicit command and key-usage policy matrix so every privileged request is allowed or denied through one reviewable path.

**Independent Test**: Attempt representative commands across allowed and disallowed roles, session states, lifecycle states, and key states, confirming the observed results match the documented policy matrix.

### Tests for User Story 1 ⚠️

- [X] T016 [P] [US1] Add protocol tests for command-matrix allow and deny cases across public, bootstrap, administrator, recovery, and key-manager roles in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/policy_command_matrix.rs
- [X] T017 [P] [US1] Add protocol tests for key-usage and key-lifecycle policy denial on signing, wrapped import, revoke, and destroy paths in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/key_policy_enforcement.rs
- [X] T018 [P] [US1] Add contract tests for policy-command-matrix coverage and bounded denial-class encoding in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/policy_command_vectors.rs
- [X] T019 [P] [US1] Add host probe assertions for representative role/state/key-policy allow and deny decisions in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 1

- [X] T020 [P] [US1] Implement the static command-policy matrix and developer-only visibility rules in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T021 [P] [US1] Implement fixed-order policy evaluation for command visibility, lifecycle state, session freshness, and role checks in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T022 [P] [US1] Implement key-policy overlay checks for usage mask, algorithm compatibility, export policy, and key lifecycle state in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T023 [US1] Route every security-relevant command dispatch through the centralized policy engine before execution in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T024 [US1] Emit bounded policy denial classes instead of scattered legacy denials in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T025 [US1] Integrate policy-aware command catalog filtering and developer-mode exclusions in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T026 [US1] Update operator-facing status and CLI rendering for policy-based command denials in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs
- [X] T027 [US1] Update the policy matrix, key-usage overlay notes, and quickstart expectations in /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/contracts/policy-command-matrix.md and /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/quickstart.md

**Checkpoint**: User Story 1 should now provide a centralized, reviewable policy MVP.

---

## Phase 4: User Story 2 - Controlled Destructive Actions (Priority: P2)

**Goal**: Require the documented approval path for destructive and high-impact operations, with stale or ambiguous approval state failing closed.

**Independent Test**: Attempt zeroize, destroy, and protected recovery actions with missing, partial, stale, and complete approvals, confirming only the approved path succeeds and all approval artifacts are consumed or invalidated correctly.

### Tests for User Story 2 ⚠️

- [X] T028 [P] [US2] Add protocol tests for approval-ticket creation, confirmation, consumption, and invalidation in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/approval_ticket_lifecycle.rs
- [X] T029 [P] [US2] Add protocol tests for destructive-action denial on missing or incomplete approval in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/protected_action_denials.rs
- [X] T030 [P] [US2] Add protocol tests for stale approval after policy revision, lifecycle change, device revision change, and reboot ambiguity in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/approval_staleness.rs
- [X] T031 [P] [US2] Add contract tests for approval-workflow payloads and denial-semantics mappings in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/policy_approval_vectors.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract/policy_denial_vectors.rs
- [X] T032 [P] [US2] Add host probe coverage for destructive-action approval and stale-ticket denial in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 2

- [X] T033 [P] [US2] Implement approval-ticket creation, confirmation, binding, and invalidation rules in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T034 [P] [US2] Extend codecs for approval-ticket responses and protected-action request bindings in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T035 [US2] Implement protected-action dispatch gates for `ExecuteZeroize`, `DestroyPersistentKey`, `RecoverToProvisioned`, and `ReactivateRecoveredProvisioning` in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T036 [US2] Persist approval tickets, invalidate them on ambiguous restore, and erase them on reset or zeroize in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs and /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T037 [US2] Enforce dual-control enablement from the persisted policy profile and fall back to single-reviewed-path rules when dual-control is disabled in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T038 [US2] Add CLI support for viewing approval-required failures and destructive-action approval progress in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs
- [X] T039 [US2] Update approval workflow, stale-ticket semantics, and destructive-action notes in /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/contracts/approval-workflow.md and /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/quickstart.md

**Checkpoint**: User Stories 1 and 2 should now enforce approval-gated destructive actions cleanly.

---

## Phase 5: User Story 3 - Reviewable Security Rules (Priority: P3)

**Goal**: Keep policy behavior explicit and auditable so every sensitive command and denial path is traceable without implementation archaeology.

**Independent Test**: Review the code and contracts for representative sensitive commands and confirm each one maps to one explicit policy rule path, one bounded denial path, and one documented approval condition if applicable.

### Tests for User Story 3 ⚠️

- [X] T040 [P] [US3] Add contract tests that assert every security-relevant command id resolves to exactly one policy rule in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/policy_coverage_vectors.rs
- [X] T041 [P] [US3] Add protocol tests for conflicting-rule, missing-reference, and multiple-ticket ambiguity failing as `internal_policy_error` in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/policy_reviewability.rs
- [X] T042 [P] [US3] Add host-side regression checks that compare documented policy expectations against observed denial classes in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 3

- [X] T043 [P] [US3] Centralize policy rule definitions and reviewable lookup helpers in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T044 [P] [US3] Implement explicit ambiguity detection for duplicate rules, unresolved key-policy references, and multiple candidate approval tickets in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T045 [US3] Add review-oriented status rendering and denial-class summaries to /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/
- [X] T046 [US3] Align the policy matrix, approval workflow, and denial semantics contracts with the implemented rule tables in /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/contracts/policy-command-matrix.md, /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/contracts/approval-workflow.md, and /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/contracts/denial-semantics.md
- [X] T047 [US3] Update the feature quickstart with review steps and representative rule-tracing examples in /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/quickstart.md

**Checkpoint**: All user stories should now be independently functional and reviewable.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final integration, cleanup, and end-to-end validation across the policy surface.

- [X] T048 [P] Add end-to-end policy regression coverage across /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [X] T049 [P] Clean up duplicated authorization branches and migrate remaining policy-sensitive checks into the centralized engine in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T050 [P] Update operator workflow notes and `rphsmtool` help text for policy and approval semantics in /home/michael/src/embedded/rp_hsm/README.md and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T051 Run the quickstart validation sequence and align any drift in /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/quickstart.md
- [X] T052 Run workspace validation commands and record completion status in /home/michael/src/embedded/rp_hsm/specs/006-policy-enforcement/tasks.md

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies, can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion and blocks all story work
- **User Story phases (Phases 3-5)**: Depend on Foundational completion
- **Polish (Phase 6)**: Depends on the desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Starts after Foundational completion and delivers the MVP policy engine
- **User Story 2 (P2)**: Starts after Foundational completion and depends on the centralized policy engine from US1
- **User Story 3 (P3)**: Starts after Foundational completion and depends on the shared policy and approval structures from US1 and US2 for reviewability checks

### Within Each User Story

- Required tests must exist and fail before implementation is considered complete
- Policy structures before dispatch integration
- Codecs before end-to-end command wiring
- Approval persistence before destructive-action probe validation
- Contract alignment before final quickstart sign-off

### Parallel Opportunities

- Setup tasks `T002-T004`
- Foundational tasks `T006-T008` and `T010-T014`
- US1 tests `T016-T019` and implementation trio `T020-T022`
- US2 tests `T028-T032` and implementation pair `T033-T034`
- US3 tests `T040-T042` and implementation pair `T043-T044`
- Polish tasks `T048-T050`

---

## Parallel Example: User Story 1

```bash
# Launch US1 validation tasks together:
Task: "Add protocol tests for command-matrix allow and deny cases across roles in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/policy_command_matrix.rs"
Task: "Add protocol tests for key-usage and key-lifecycle policy denial in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/key_policy_enforcement.rs"
Task: "Add host probe assertions for representative role/state/key-policy allow and deny decisions in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs"

# Launch US1 implementation tasks together:
Task: "Implement the static command-policy matrix and developer-only visibility rules in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs"
Task: "Implement fixed-order policy evaluation for command visibility, lifecycle state, session freshness, and role checks in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs"
Task: "Implement key-policy overlay checks for usage mask, algorithm compatibility, export policy, and key lifecycle state in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. Validate command-matrix and key-policy behavior independently before moving on

### Incremental Delivery

1. Setup + Foundational
2. User Story 1: centralized command and key policy enforcement
3. User Story 2: approval-gated destructive actions
4. User Story 3: reviewability and ambiguity handling
5. Polish and hardware validation

### Suggested MVP Scope

- Phase 1
- Phase 2
- Phase 3 only

---

## Notes

- [P] tasks are parallelizable because they touch separate files or independent validation surfaces
- Each user story remains independently testable against its own acceptance criteria
- Required misuse-case and malformed-input tests are included because this feature changes an authorization and persistence trust boundary
