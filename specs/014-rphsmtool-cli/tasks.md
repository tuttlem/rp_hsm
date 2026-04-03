# Tasks: rphsmtool CLI

**Input**: Design documents from `/specs/014-rphsmtool-cli/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, and misuse-case tests are REQUIRED for this feature because it adds a new user-facing command surface, device-selection logic, host-side secret handling, and capability-gated operation flow.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g. `US1`, `US2`, `US3`)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create the CLI feature surface and align roadmap and operator docs.

- [X] T001 Capture the `rphsmtool` command surface and discovery goals in /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/contracts/
- [X] T002 [P] Add roadmap and README notes for the user-facing CLI surface in /home/michael/src/embedded/rp_hsm/ROADMAP.md and /home/michael/src/embedded/rp_hsm/README.md
- [X] T003 [P] Create the host-tools module layout for `rphsmtool` in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/ and /home/michael/src/embedded/rp_hsm/host_tools/src/
- [X] T004 [P] Reserve CLI-focused test modules in /home/michael/src/embedded/rp_hsm/host_tools/src/ and /home/michael/src/embedded/rp_hsm/protocol/tests/

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Build the shared host-side infrastructure that every CLI verb depends on.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T005 Define host-side command dispatch boundaries and shared CLI entrypoints in /home/michael/src/embedded/rp_hsm/host_tools/src/lib.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T006 [P] Define argument parsing, verb selection, and `--device` option handling in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [X] T007 [P] Implement bounded stdout/stderr output helpers and exit-code mapping in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs
- [X] T008 [P] Implement reusable host-side protocol/session client helpers in /home/michael/src/embedded/rp_hsm/host_tools/src/lib.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [X] T009 [P] Define device-discovery data structures, compatibility checks, and selection outcomes in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs
- [X] T010 Add malformed-response, ambiguous-device, and unsupported-capability failure handling to shared CLI paths in /home/michael/src/embedded/rp_hsm/host_tools/src/lib.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs
- [X] T011 [P] Add foundational host-side tests for argument parsing, output separation, and fail-closed exit behavior in /home/michael/src/embedded/rp_hsm/host_tools/src/
- [X] T012 [P] Document secret-buffer handling, device-selection safety, and developer-mode boundaries in /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/quickstart.md and /home/michael/src/embedded/rp_hsm/README.md

**Checkpoint**: Shared CLI infrastructure, safety boundaries, and reusable client logic are ready.

---

## Phase 3: User Story 1 - Discover And Target A Device (Priority: P1) 🎯 MVP

**Goal**: Let operators discover compatible RP HSM devices and select a safe target explicitly or implicitly.

**Independent Test**: Connect one or more compatible devices, run `rphsmtool find`, then run a read-only command with and without `--device` and confirm the tool either selects the only compatible device or fails with a clear ambiguity error.

### Tests for User Story 1 ⚠️

- [X] T013 [P] [US1] Add discovery and device-selection tests for zero, one, and multiple compatible devices in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs
- [X] T014 [P] [US1] Add misuse-case tests for invalid selectors and disappearing devices in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs
- [X] T015 [P] [US1] Add contract-alignment checks for discovery and selection rules in /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/contracts/device-discovery.md and /home/michael/src/embedded/rp_hsm/README.md

### Implementation for User Story 1

- [X] T016 [P] [US1] Implement `rphsmtool find` device enumeration in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T017 [US1] Implement explicit `--device` selection and implicit single-device resolution in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs
- [X] T018 [US1] Implement fail-closed ambiguity and missing-device error paths in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T019 [US1] Implement a read-only status command that exercises resolved device targeting in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T020 [US1] Update discovery examples and safe-selection notes in /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/contracts/cli-commands.md, /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/contracts/device-discovery.md, and /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/quickstart.md

**Checkpoint**: User Story 1 is independently functional and testable.

---

## Phase 4: User Story 2 - Use Unix-Style Data Flows (Priority: P2)

**Goal**: Make supported commands safe and predictable in stdin/stdout pipelines.

**Independent Test**: Run `rphsmtool get-random` and other supported commands in pipelines and confirm stdout contains only results while diagnostics stay on stderr.

### Tests for User Story 2 ⚠️

- [X] T021 [P] [US2] Add output-separation tests for raw-byte and structured commands in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs
- [X] T022 [P] [US2] Add stdin-handling and empty-stdin misuse-case tests in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [X] T023 [P] [US2] Add command-level tests for `get-random` stdout behavior and failure-path stderr behavior in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs

### Implementation for User Story 2

- [X] T024 [P] [US2] Implement stdin readers and bounded input handling in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [X] T025 [P] [US2] Implement stdout renderers for raw-byte and structured output modes in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs
- [X] T026 [US2] Implement `rphsmtool get-random` using the shared host client in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T027 [US2] Ensure diagnostics, usage failures, and device errors never leak partial result data in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T028 [US2] Update Unix-style I/O expectations and examples in /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/contracts/io-behavior.md, /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/contracts/cli-commands.md, and /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/quickstart.md

**Checkpoint**: User Stories 1 and 2 both work independently.

---

## Phase 5: User Story 3 - Normalize HSM Operations For Users (Priority: P3)

**Goal**: Provide stable capability-aligned user verbs that hide session and framing mechanics without overstating unsupported features.

**Independent Test**: Execute representative commands such as `find`, `status`, `get-random`, `list-keys`, and `get-key-metadata`, and confirm unsupported future verbs fail explicitly rather than pretending to work.

### Tests for User Story 3 ⚠️

- [X] T029 [P] [US3] Add capability-gating and unsupported-verb denial tests in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [X] T030 [P] [US3] Add session-expiry and reauthentication workflow tests for privileged commands in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [X] T031 [P] [US3] Add command-surface regression tests for `list-keys` and `get-key-metadata` in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs

### Implementation for User Story 3

- [X] T032 [P] [US3] Implement capability inspection and verb gating in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [X] T033 [P] [US3] Implement authenticated key-store commands `list-keys` and `get-key-metadata` in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T034 [US3] Implement host-side authentication/session handling so users do not manage counters or framing directly in /home/michael/src/embedded/rp_hsm/host_tools/src/lib.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [X] T035 [US3] Implement explicit unsupported-operation reporting for reserved future verbs in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs
- [X] T036 [US3] Update user-facing command contracts and capability notes in /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/contracts/cli-commands.md, /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/contracts/io-behavior.md, and /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/quickstart.md

**Checkpoint**: All user stories are independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Finalize documentation, validation, and command-surface consistency.

- [X] T037 [P] Add end-to-end CLI regression coverage in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs and /home/michael/src/embedded/rp_hsm/README.md
- [X] T038 [P] Clean up shared host client boundaries, duplicated command-shape constants, and dead code in /home/michael/src/embedded/rp_hsm/host_tools/src/lib.rs, /home/michael/src/embedded/rp_hsm/host_tools/src/cli/, and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/
- [X] T039 Update operator workflow and cargo command documentation for `rphsmtool` in /home/michael/src/embedded/rp_hsm/README.md
- [X] T040 Run the quickstart validation sequence and align any drift in /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/quickstart.md
- [X] T041 Run workspace validation commands and record completion status in /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/tasks.md

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies
- **Foundational (Phase 2)**: Depends on Setup and blocks all user stories
- **User Stories (Phases 3-5)**: Depend on Foundational completion
- **Polish (Phase 6)**: Depends on desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Starts after Foundational and delivers the MVP
- **User Story 2 (P2)**: Starts after Foundational and depends on shared output and command infrastructure, not on US1 completion
- **User Story 3 (P3)**: Starts after Foundational and integrates with shared client/session logic while remaining independently testable

### Within Each User Story

- Required misuse-case and command-surface tests should exist before implementation is considered complete
- Discovery and selection rules before command verbs that depend on them
- I/O safety before data-bearing commands
- Capability gating before future-verb exposure
- Documentation alignment before final validation

### Parallel Opportunities

- Setup tasks `T002-T004`
- Foundational tasks `T006-T009` and `T011-T012`
- US1 tests `T013-T015` and implementation pair `T016-T017`
- US2 tests `T021-T023` and implementation pair `T024-T025`
- US3 tests `T029-T031` and implementation pair `T032-T033`
- Polish tasks `T037-T038`

---

## Parallel Example: User Story 1

```bash
# Launch discovery validation tasks together:
Task: "Add discovery and device-selection tests for zero, one, and multiple compatible devices in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs"
Task: "Add misuse-case tests for invalid selectors and disappearing devices in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs"
Task: "Add contract-alignment checks for discovery and selection rules in /home/michael/src/embedded/rp_hsm/specs/014-rphsmtool-cli/contracts/device-discovery.md and /home/michael/src/embedded/rp_hsm/README.md"

# Launch discovery implementation tasks together:
Task: "Implement rphsmtool find device enumeration in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs"
Task: "Implement explicit --device selection and implicit single-device resolution in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. Validate discovery, explicit selection, and implicit single-device resolution

### Incremental Delivery

1. Setup + Foundational
2. User Story 1: discovery and safe device targeting
3. User Story 2: Unix-style stdin/stdout data flows
4. User Story 3: capability-aligned verbs and host-side session normalization
5. Polish and validation

### Suggested MVP Scope

- Phase 1
- Phase 2
- Phase 3 only

---

## Notes

- [P] tasks are parallelizable because they touch different files or independent test and documentation surfaces
- Each user story remains independently testable against its own acceptance criteria
- The CLI must remain honest about unsupported firmware capabilities rather than inventing placeholder behavior
