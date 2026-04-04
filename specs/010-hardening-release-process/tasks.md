# Tasks: Hardening and Release Process

**Input**: Design documents from `/specs/010-hardening-release-process/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Review-check, evidence-completeness, misuse-coverage, dependency-review, and release-record validation tasks are required for this feature because release approval is itself the trust boundary being hardened.

**Organization**: Tasks are grouped by user story so each story can be implemented and tested independently.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (`US1`, `US2`, `US3`)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Capture the release-hardening scope and reserve the repo guidance surfaces this feature will tighten.

- [X] T001 Capture the `010-hardening-release-process` release-bar scope, evidence model, and approval boundary in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/contracts/
- [X] T002 [P] Add roadmap and README notes for release readiness, hardening evidence, and fail-closed approval expectations in /home/michael/src/embedded/rp_hsm/README.md and /home/michael/src/embedded/rp_hsm/ROADMAP.md
- [X] T003 [P] Reserve repository guidance sections for release evidence, dependency review, and exception handling in /home/michael/src/embedded/rp_hsm/SECURITY.md and /home/michael/src/embedded/rp_hsm/README.md
- [X] T004 [P] Reserve feature quickstart sections for candidate identity, hardening review, and approval decisions in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/quickstart.md

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared release-evidence, hardening-matrix, and exception-record structures that must exist before user-story-specific workflow details can be completed.

**⚠️ CRITICAL**: No user story work should begin until this phase is complete.

- [X] T005 Define the canonical release-evidence structure, mandatory sections, and fail-closed approval rules in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/contracts/release-evidence-schema.md
- [X] T006 [P] Define the canonical hardening-matrix categories and required evidence classes in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/contracts/hardening-matrix.md
- [X] T007 [P] Define the exception and approval workflow, non-waivable rules, and sensitive-material handling in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/contracts/exception-and-approval-workflow.md
- [X] T008 [P] Align the `Release Evidence Set`, `Hardening Check`, `Release Exception`, and `Approved Artifact Record` entities with concrete record fields and state transitions in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/data-model.md
- [X] T009 Create a repo-tracked release-evidence template for candidate records in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-evidence-template.md
- [X] T010 [P] Create a repo-tracked hardening-matrix template for candidate review snapshots in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/hardening-matrix-template.md
- [X] T011 [P] Create a repo-tracked release-exception template for approved deviations in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-exception-template.md
- [X] T012 [P] Create a repo-tracked approved-artifact record template in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/approved-artifact-template.md
- [X] T013 [P] Document the baseline workspace validation command set and evidence-capture expectations in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/quickstart.md and /home/michael/src/embedded/rp_hsm/README.md
- [X] T014 Record the bounded dependency/build review approach for this Cargo workspace in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/research.md and /home/michael/src/embedded/rp_hsm/SECURITY.md

**Checkpoint**: Shared release records, templates, and fail-closed review rules are ready for story work.

---

## Phase 3: User Story 1 - Evidence-Based Release Readiness (Priority: P1) 🎯 MVP

**Goal**: Make release approval depend on a complete, reviewable evidence set rather than informal confidence.

**Independent Test**: Review a candidate release record built from the new templates and confirm that missing evidence blocks approval while a complete record can proceed.

### Tests for User Story 1 ⚠️

- [X] T015 [P] [US1] Add an incomplete-evidence example release record showing approval must fail in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/incomplete-release-evidence.md
- [X] T016 [P] [US1] Add a complete-evidence example release record showing approval can proceed in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/complete-release-evidence.md
- [X] T017 [P] [US1] Add a checklist-driven review example proving missing artifact identity or missing evidence blocks approval in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/release-review-walkthrough.md

### Implementation for User Story 1

- [X] T018 [P] [US1] Fill the release-evidence template with explicit candidate identity, evidence references, and approval-state rules in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-evidence-template.md
- [X] T019 [P] [US1] Fill the approved-artifact template with required artifact identity, approval basis, and carried-exception sections in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/approved-artifact-template.md
- [X] T020 [P] [US1] Document the review-ready vs approved vs rejected flow for candidate records in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/contracts/release-evidence-schema.md and /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/data-model.md
- [X] T021 [US1] Add operator/reviewer guidance explaining that release decisions are evidence-based and fail closed on missing sections in /home/michael/src/embedded/rp_hsm/README.md and /home/michael/src/embedded/rp_hsm/SECURITY.md
- [X] T022 [US1] Align the candidate-review quickstart and example workflow with the implemented release-evidence templates in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/quickstart.md and /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/release-review-walkthrough.md

**Checkpoint**: Release approval should now be tied to explicit candidate evidence instead of informal judgment.

---

## Phase 4: User Story 2 - Deliberate Abuse and Failure Testing (Priority: P2)

**Goal**: Require parser abuse, misuse, invalid-state, and persistence-corruption coverage as part of release readiness.

**Independent Test**: Review the hardening matrix for a candidate and confirm the required parser, misuse, replay, corruption, and recovery classes are all covered by evidence or explicit exceptions.

### Tests for User Story 2 ⚠️

- [X] T023 [P] [US2] Add a hardening-matrix example showing parser abuse, replay, and invalid-state evidence coverage in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/hardening-matrix-parser-and-misuse.md
- [X] T024 [P] [US2] Add a hardening-matrix example showing persistence corruption, audit recovery, and update recovery coverage in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/hardening-matrix-corruption-and-recovery.md
- [X] T025 [P] [US2] Add a blocked-review example where a single missing hardening class prevents approval in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/hardening-gap-blocks-release.md

### Implementation for User Story 2

- [X] T026 [P] [US2] Expand the hardening-matrix contract to map each required verification class to concrete repo evidence sources in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/contracts/hardening-matrix.md
- [X] T027 [P] [US2] Fill the hardening-matrix template with status, evidence-reference, and candidate-scope sections for every required class in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/hardening-matrix-template.md
- [X] T028 [P] [US2] Document how release reviewers identify acceptable software-test evidence versus required live-validation evidence in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/quickstart.md and /home/michael/src/embedded/rp_hsm/README.md
- [X] T029 [US2] Add explicit fail-closed language that no passing happy-path class compensates for omitted hardening coverage in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/contracts/hardening-matrix.md and /home/michael/src/embedded/rp_hsm/SECURITY.md
- [X] T030 [US2] Align the release-evidence template and walkthrough examples so required hardening classes are visible during approval review in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-evidence-template.md and /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/release-review-walkthrough.md

**Checkpoint**: Required misuse, corruption, and fail-safe validation classes should now be part of the release bar.

---

## Phase 5: User Story 3 - Review of Supply and Build Risk (Priority: P3)

**Goal**: Require dependency review, build-input review, artifact identity, and explicit exception handling as part of the trusted release process.

**Independent Test**: Review a candidate package with dependency changes and confirm the release record shows what changed, what artifact was built, and whether any exception was explicitly accepted.

### Tests for User Story 3 ⚠️

- [X] T031 [P] [US3] Add a dependency-review example covering a changed `Cargo.lock` and security-relevant impact summary in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/dependency-review-example.md
- [X] T032 [P] [US3] Add a build-review example covering artifact identity, build commands, and provenance recording in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/build-review-example.md
- [X] T033 [P] [US3] Add an approved-exception example tied to one candidate artifact and one required check in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/release-exception-example.md

### Implementation for User Story 3

- [X] T034 [P] [US3] Fill the release-exception template with rationale, mitigation, approver, and revisit requirements in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-exception-template.md
- [X] T035 [P] [US3] Add explicit dependency-review and build-review sections to the release-evidence template and approved-artifact template in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-evidence-template.md and /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/approved-artifact-template.md
- [X] T036 [P] [US3] Document the bounded Cargo-workspace dependency review process in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/contracts/release-evidence-schema.md and /home/michael/src/embedded/rp_hsm/SECURITY.md
- [X] T037 [US3] Document non-waivable approval expectations for artifact identity, review traceability, and unresolved-risk visibility in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/contracts/exception-and-approval-workflow.md and /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/quickstart.md
- [X] T038 [US3] Align the supply/build review examples and approval flow with the final release-record templates in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/dependency-review-example.md, /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/build-review-example.md, and /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/release-exception-example.md

**Checkpoint**: Dependency review, build review, artifact identity, and exception handling should now be part of the release-readiness process.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final integration, repository guidance cleanup, and release-process validation across all templates and examples.

- [X] T039 [P] Add a consolidated release-readiness checklist for this repo in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-readiness-checklist.md
- [X] T040 [P] Clean up duplicated release-bar, exception, and evidence language across /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/contracts/, /home/michael/src/embedded/rp_hsm/README.md, and /home/michael/src/embedded/rp_hsm/SECURITY.md
- [X] T041 [P] Update repository guidance so future features know to feed release records with validation evidence in /home/michael/src/embedded/rp_hsm/README.md, /home/michael/src/embedded/rp_hsm/SECURITY.md, and /home/michael/src/embedded/rp_hsm/ROADMAP.md
- [X] T042 Run the hardening/release quickstart walkthrough against the templates and align any drift in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/quickstart.md
- [X] T043 Run documentation consistency validation and record completion status in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/tasks.md

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies, can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion and blocks all user-story work
- **User Story phases (Phases 3-5)**: Depend on Foundational completion
- **Polish (Phase 6)**: Depends on the desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Starts after Foundational completion and delivers the MVP release-evidence approval flow
- **User Story 2 (P2)**: Starts after Foundational completion and depends on the shared evidence and hardening-matrix structures from Phase 2
- **User Story 3 (P3)**: Starts after Foundational completion and depends on the shared evidence, exception, and approval structures from Phase 2

### Within Each User Story

- Evidence and review examples should be created before final workflow wording is considered complete
- Shared templates before story-specific examples
- Fail-closed approval rules before quickstart sign-off
- Repo guidance alignment after contract and template behavior is fixed

### Parallel Opportunities

- Setup tasks `T002-T004`
- Foundational tasks `T006-T008` and `T010-T013`
- US1 tests `T015-T017` and implementation trio `T018-T020`
- US2 tests `T023-T025` and implementation trio `T026-T028`
- US3 tests `T031-T033` and implementation trio `T034-T036`
- Polish tasks `T039-T041`

---

## Parallel Example: User Story 1

```bash
# Launch US1 review-example tasks together:
Task: "Add an incomplete-evidence example release record showing approval must fail in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/incomplete-release-evidence.md"
Task: "Add a complete-evidence example release record showing approval can proceed in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/complete-release-evidence.md"
Task: "Add a checklist-driven review example proving missing artifact identity or missing evidence blocks approval in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/release-review-walkthrough.md"

# Launch US1 implementation tasks together:
Task: "Fill the release-evidence template with explicit candidate identity, evidence references, and approval-state rules in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-evidence-template.md"
Task: "Fill the approved-artifact template with required artifact identity, approval basis, and carried-exception sections in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/approved-artifact-template.md"
Task: "Document the review-ready vs approved vs rejected flow for candidate records in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/contracts/release-evidence-schema.md and /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/data-model.md"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. Validate that missing evidence blocks approval and complete evidence supports a bounded release decision

### Incremental Delivery

1. Setup + Foundational
2. User Story 1: evidence-based release approval
3. User Story 2: required hardening and abuse-case coverage
4. User Story 3: dependency/build review and exception handling
5. Polish and repository-wide release guidance validation

### Suggested MVP Scope

- Phase 1
- Phase 2
- Phase 3 only

---

## Notes

- [P] tasks are parallelizable because they touch separate documents, templates, or example records
- Each user story remains independently testable against its own acceptance criteria
- This feature hardens release discipline and evidence review without expanding the runtime firmware attack surface
