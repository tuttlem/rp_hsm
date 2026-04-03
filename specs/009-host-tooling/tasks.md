# Tasks: Host Tooling

**Input**: Design documents from `/specs/009-host-tooling/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: CLI-behavior, host-integration, transport-failure, packaging, and live-workflow tests are required for this feature because it defines the supported operator surface, machine-consumable host boundary, and failure semantics for host-side transport conditions.

**Organization**: Tasks are grouped by user story so each story can be implemented and tested independently.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (`US1`, `US2`, `US3`)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Capture the consolidation boundary and reserve the validation/doc surfaces for the supported host tooling stack.

- [X] T001 Capture the `009-host-tooling` consolidation scope, supported boundaries, and workflow expectations in /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/contracts/
- [X] T002 [P] Add README and roadmap notes clarifying `rphsmtool` as the canonical operator CLI and `probe_protocol` as engineering-only in /home/michael/src/embedded/rp_hsm/README.md and /home/michael/src/embedded/rp_hsm/ROADMAP.md
- [X] T003 [P] Reserve host-tools test coverage for CLI behavior, transport failures, and supported client-surface conformance in /home/michael/src/embedded/rp_hsm/host_tools/src/lib.rs and /home/michael/src/embedded/rp_hsm/host_tools/tests/
- [X] T004 [P] Reserve operator-validation and engineering-validation sections in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared host-side error, discovery, output, and supported-client structures that must exist before user-facing consolidation can be completed.

**⚠️ CRITICAL**: No user story work should begin until this phase is complete.

- [X] T005 Define the supported host-tooling boundary, error taxonomy, and capability-exposure decision points in /home/michael/src/embedded/rp_hsm/host_tools/src/lib.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs
- [X] T006 [P] Add transport-condition result types and normalized busy/permission/missing-device/incompatible-firmware mapping in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs
- [X] T007 [P] Centralize serial-device discovery, implicit-selection, and re-enumeration handling helpers in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs
- [X] T008 [P] Define canonical stdout/stderr rendering helpers and structured operator-output rules in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs
- [X] T009 Add shared CLI command-group metadata and help-surface classification for user, admin, advanced, and engineering-only commands in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [X] T010 [P] Add foundational tests for transport-failure classification and implicit-device-selection rules in /home/michael/src/embedded/rp_hsm/host_tools/tests/transport_conditions.rs and /home/michael/src/embedded/rp_hsm/host_tools/tests/device_selection.rs
- [X] T011 [P] Add foundational tests for CLI stdout/stderr separation and unsupported-command reporting in /home/michael/src/embedded/rp_hsm/host_tools/tests/cli_output_contract.rs
- [X] T012 [P] Add foundational tests for supported client-surface result mapping and denial-vs-host-error separation in /home/michael/src/embedded/rp_hsm/host_tools/tests/client_surface_contract.rs
- [X] T013 [P] Document packaging, install, permission, and competing-service expectations in /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/contracts/transport-and-packaging.md and /home/michael/src/embedded/rp_hsm/README.md
- [X] T014 Record the host-tooling completion rule for newly added firmware capabilities in /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/contracts/cli-surface.md and /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/contracts/host-client-surface.md

**Checkpoint**: Shared host-side transport, output, and integration boundaries are ready for story work.

---

## Phase 3: User Story 1 - Complete Operator Workflows (Priority: P1) 🎯 MVP

**Goal**: Make `rphsmtool` the complete supported operator surface for approved workflows, with clear host-side failure handling.

**Independent Test**: Run representative operator flows through `rphsmtool`, including device discovery, provisioning, diagnostics, and failure cases, confirming supported commands succeed cleanly and host-side access failures are explained without requiring `probe_protocol`.

### Tests for User Story 1 ⚠️

- [X] T015 [P] [US1] Add CLI tests for grouped help output, canonical command visibility, and reserved-command behavior in /home/michael/src/embedded/rp_hsm/host_tools/tests/rphsmtool_help_surface.rs
- [X] T016 [P] [US1] Add CLI tests for busy-port, permission-denied, and no-device operator messaging in /home/michael/src/embedded/rp_hsm/host_tools/tests/rphsmtool_transport_errors.rs
- [X] T017 [P] [US1] Add live-workflow probe coverage for canonical operator commands and self-reset baseline handling in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 1

- [X] T018 [P] [US1] Consolidate supported operator commands, aliases, and help-group presentation in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs, /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs, and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T019 [P] [US1] Improve device-open failure handling and remediation hints for busy ports, missing `uucp` membership, and competing services in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs
- [X] T020 [P] [US1] Close remaining supported workflow gaps and align command wrappers with implemented firmware capabilities in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs
- [X] T021 [US1] Ensure operator commands keep stdout result-only and stderr diagnostics-only across success and failure paths in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T022 [US1] Align user-facing operator workflows, examples, and error-handling guidance in /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/contracts/cli-surface.md, /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/quickstart.md, and /home/michael/src/embedded/rp_hsm/README.md

**Checkpoint**: `rphsmtool` should now be the usable canonical operator surface with clear host-side failure semantics.

---

## Phase 4: User Story 2 - Stable Integration Surface (Priority: P2)

**Goal**: Provide a defined machine-consumable host-side boundary so integrations do not scrape CLI text.

**Independent Test**: Build representative host-side calls against `host_tools::client`, confirm typed results distinguish device denials from host failures, and confirm supported workflows can be consumed without parsing `rphsmtool` output.

### Tests for User Story 2 ⚠️

- [X] T023 [P] [US2] Add tests for typed client results across successful operations, device denials, and host transport failures in /home/michael/src/embedded/rp_hsm/host_tools/tests/client_result_mapping.rs
- [X] T024 [P] [US2] Add tests for supported device-discovery and explicit-device-selection APIs in /home/michael/src/embedded/rp_hsm/host_tools/tests/client_discovery_api.rs
- [X] T025 [P] [US2] Add tests for capability-exposure conformance so new supported firmware commands are intentionally classified as operator, client-only, or engineering-only in /home/michael/src/embedded/rp_hsm/host_tools/tests/capability_exposure_rules.rs

### Implementation for User Story 2

- [X] T026 [P] [US2] Refactor /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs into a clearly supported integration surface with typed request helpers and typed result structures
- [X] T027 [P] [US2] Export the supported host client boundary and supporting result/error types from /home/michael/src/embedded/rp_hsm/host_tools/src/lib.rs
- [X] T028 [P] [US2] Separate CLI-only rendering logic from reusable machine-consumable client logic in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T029 [US2] Document the supported host integration boundary, non-goals, and anti-scraping rule in /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/contracts/host-client-surface.md and /home/michael/src/embedded/rp_hsm/README.md
- [X] T030 [US2] Add library usage examples for discovery, status, and one authenticated operation in /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/quickstart.md and /home/michael/src/embedded/rp_hsm/README.md

**Checkpoint**: Integrators should now have a supported typed host-side surface that does not depend on CLI text scraping.

---

## Phase 5: User Story 3 - Clear Product vs Engineering Boundaries (Priority: P3)

**Goal**: Keep operator tooling, supported integration, and engineering validation clearly separated so product use cases do not depend on probe internals.

**Independent Test**: Confirm operators can follow the documented `rphsmtool` workflow, integrators can use `host_tools::client`, and engineering-only commands remain clearly labeled and isolated to `probe_protocol` or developer-marked paths.

### Tests for User Story 3 ⚠️

- [X] T031 [P] [US3] Add tests for engineering-only command labeling and hidden-by-default help behavior in /home/michael/src/embedded/rp_hsm/host_tools/tests/engineering_surface_separation.rs
- [X] T032 [P] [US3] Add tests for packaging/install guidance accuracy and Cargo alias availability in /home/michael/src/embedded/rp_hsm/host_tools/tests/packaging_surface.rs and /home/michael/src/embedded/rp_hsm/.cargo/config.toml
- [X] T033 [P] [US3] Add live-validation coverage confirming `probe_protocol` remains engineering-only while `rphsmtool` covers the approved operator path in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs

### Implementation for User Story 3

- [X] T034 [P] [US3] Tighten `probe_protocol` messaging and boundaries so it is explicitly described as an engineering validation tool in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs and /home/michael/src/embedded/rp_hsm/README.md
- [X] T035 [P] [US3] Tighten `rphsmtool` help text, command descriptions, and developer-command labeling so product workflows are distinguishable from engineering flows in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs
- [X] T036 [P] [US3] Align Cargo aliases, invocation guidance, and install expectations for `cargo rphsmtool` and probe usage in /home/michael/src/embedded/rp_hsm/.cargo/config.toml, /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/contracts/transport-and-packaging.md, and /home/michael/src/embedded/rp_hsm/README.md
- [X] T037 [US3] Add a documented host-tooling capability-exposure checklist so each new firmware feature triggers an explicit operator/client/engineering decision in /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/contracts/cli-surface.md and /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/quickstart.md
- [X] T038 [US3] Align the product-vs-engineering examples, packaging notes, and support boundaries across /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/contracts/cli-surface.md, /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/contracts/host-client-surface.md, and /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/quickstart.md

**Checkpoint**: Operator, integration, and engineering surfaces should now be clearly separated and documented.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final cleanup, quickstart validation, and completion recording across the host-tooling surface.

- [X] T039 [P] Add end-to-end host-tooling regression coverage across /home/michael/src/embedded/rp_hsm/host_tools/tests/ and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs
- [X] T040 [P] Clean up duplicated host-side device-selection, error-rendering, and command-dispatch helpers in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs, /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs, and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [X] T041 [P] Update operator workflow notes and default help examples for transport contention, permissions, and packaging expectations in /home/michael/src/embedded/rp_hsm/README.md and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [X] T042 Run the host-tooling quickstart validation sequence and align any drift in /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/quickstart.md
- [X] T043 Run host-tools validation commands and record completion status in /home/michael/src/embedded/rp_hsm/specs/009-host-tooling/tasks.md

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies, can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion and blocks all user-story work
- **User Story phases (Phases 3-5)**: Depend on Foundational completion
- **Polish (Phase 6)**: Depends on the desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Starts after Foundational completion and delivers the canonical operator surface
- **User Story 2 (P2)**: Starts after Foundational completion and depends on the shared host-side error and discovery structures from Phase 2
- **User Story 3 (P3)**: Starts after Foundational completion and depends on the clarified CLI and supported-client boundaries delivered by US1 and US2

### Within Each User Story

- Tests for supported behavior and failure modes should exist before implementation is considered complete
- Shared host-client and discovery helpers before CLI rendering cleanup
- CLI behavior before documentation sign-off
- Product-vs-engineering boundary updates before packaging and quickstart sign-off

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
# Launch US1 validation tasks together:
Task: "Add CLI tests for grouped help output, canonical command visibility, and reserved-command behavior in /home/michael/src/embedded/rp_hsm/host_tools/tests/rphsmtool_help_surface.rs"
Task: "Add CLI tests for busy-port, permission-denied, and no-device operator messaging in /home/michael/src/embedded/rp_hsm/host_tools/tests/rphsmtool_transport_errors.rs"
Task: "Add live-workflow probe coverage for canonical operator commands and self-reset baseline handling in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs"

# Launch US1 implementation tasks together:
Task: "Consolidate supported operator commands, aliases, and help-group presentation in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs, /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs, and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs"
Task: "Improve device-open failure handling and remediation hints for busy ports, missing uucp membership, and competing services in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/device.rs"
Task: "Close remaining supported workflow gaps and align command wrappers with implemented firmware capabilities in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. Validate that `rphsmtool` covers the supported operator path and explains host-side access failures cleanly

### Incremental Delivery

1. Setup + Foundational
2. User Story 1: canonical operator CLI and transport-failure handling
3. User Story 2: supported machine-consumable client surface
4. User Story 3: product-vs-engineering boundary, packaging, and support clarity
5. Polish and quickstart validation

### Suggested MVP Scope

- Phase 1
- Phase 2
- Phase 3 only

---

## Notes

- [P] tasks are parallelizable because they touch separate files or independent validation surfaces
- Each user story remains independently testable against its own acceptance criteria
- This feature consolidates and hardens existing host tooling rather than introducing the first CLI from scratch
