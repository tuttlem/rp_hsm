# Tasks: Broadened Crypto Suite

**Input**: Design documents from `/specs/017-crypto-suite-expansion/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, and misuse-case tests are REQUIRED because this feature changes the crypto command surface, key handling, export policy, and supported operator workflows.

**Regression**: This feature changes firmware, persistent key metadata, authorization-sensitive crypto paths, and the supported host/user surface, so bounded `rphsmtool` and live hardware regression are REQUIRED before closeout.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this belongs to (e.g. `US1`, `US2`, `US3`)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Capture the broadened crypto-suite direction in the shared docs and reserve the new operator surface.

- [x] T001 Capture the `017-crypto-suite-expansion` scope and first-shipping suite in [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts)
- [x] T002 [P] Extend roadmap and operator guidance for sender interoperability, MAC/derive, and wrapped export in [/home/michael/src/embedded/rp_hsm/ROADMAP.md](/home/michael/src/embedded/rp_hsm/ROADMAP.md) and [/home/michael/src/embedded/rp_hsm/README.md](/home/michael/src/embedded/rp_hsm/README.md)
- [x] T003 [P] Reserve CLI help placeholders for `mac`, `verify-mac`, `derive`, `export-wrapped-key`, and sender interoperability helpers in [/home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs)
- [x] T004 [P] Capture feature-specific threat assumptions, regression scope, and sender-side workflow expectations in [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md) and [/home/michael/src/embedded/rp_hsm/SECURITY.md](/home/michael/src/embedded/rp_hsm/SECURITY.md)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Define shared protocol, state, and persistence changes that every story depends on.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [x] T005 Define new command IDs, capability flags, and algorithm/profile identifiers for MAC, derive, wrapped export, and sender helpers in [/home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs)
- [x] T006 [P] Extend managed key kinds, usage flags, export policy, and algorithm profile tables in [/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs)
- [x] T007 [P] Add codec framing for MAC, derive, wrapped export, and sender interoperability payloads in [/home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs)
- [x] T008 [P] Add typed host client request/response models for the broadened suite in [/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs)
- [x] T009 Implement fail-closed parser dispatch stubs and shared bounded denial mapping for the new workflows in [/home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs)
- [x] T010 Define persistent storage handling for managed MAC keys, key-agreement keys, and wrapped-export policy state in [/home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs](/home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs)
- [x] T011 [P] Wire restored broadened-suite state into the firmware boot path in [/home/michael/src/embedded/rp_hsm/firmware/src/main.rs](/home/michael/src/embedded/rp_hsm/firmware/src/main.rs)
- [x] T012 [P] Add shared fixtures for sender envelopes, MAC vectors, derive inputs, and wrapped export material in [/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/crypto_fixtures.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/crypto_fixtures.rs)
- [x] T013 [P] Add CLI output helpers for MAC, derive, wrapped export, and sender-envelope metadata in [/home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs) and [/home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs)
- [x] T014 Document the broadened profile naming and policy contract in [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts/crypto-suite-profiles.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts/crypto-suite-profiles.md) and [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts/operator-cli-workflows.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts/operator-cli-workflows.md)

**Checkpoint**: Foundation ready. User story implementation can now begin.

---

## Phase 3: User Story 1 - Encrypt To and From External Systems (Priority: P1) 🎯 MVP

**Goal**: Let operators use exported public recipient material with a supported sender-side workflow and decrypt those envelopes on the HSM.

**Independent Test**: Generate a managed recipient key, retrieve public material, produce a supported sender envelope, decrypt it on-device, and confirm tampered or wrong-profile envelopes are denied.

### Tests for User Story 1 ⚠️

- [x] T015 [P] [US1] Add protocol misuse-case tests for malformed, tampered, wrong-profile, and wrong-key sender envelopes in [/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/asymmetric_interoperability.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/asymmetric_interoperability.rs)
- [x] T016 [P] [US1] Add protocol tests for successful sender-envelope decrypt and public-material retrieval in [/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/asymmetric_sender_workflows.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/asymmetric_sender_workflows.rs)
- [x] T017 [P] [US1] Add host client and CLI tests for sender interoperability commands and output in [/home/michael/src/embedded/rp_hsm/host_tools/tests/sender_interoperability_cli.rs](/home/michael/src/embedded/rp_hsm/host_tools/tests/sender_interoperability_cli.rs)

### Implementation for User Story 1

- [x] T018 [P] [US1] Implement sender-envelope profile metadata, public export rules, and interoperability helpers in [/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs)
- [x] T019 [US1] Implement sender-envelope validation and decrypt handlers in [/home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs)
- [x] T020 [P] [US1] Expose sender interoperability commands and public-material workflows through the host client in [/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs)
- [x] T021 [US1] Implement `rphsmtool` sender interoperability verbs and help text in [/home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs), [/home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs), and [/home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs)
- [x] T022 [US1] Align sender-side operator documentation and examples with the supported envelope workflow in [/home/michael/src/embedded/rp_hsm/README.md](/home/michael/src/embedded/rp_hsm/README.md), [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts/interoperability-and-derivation.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts/interoperability-and-derivation.md), and [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md)

**Checkpoint**: User Story 1 should now be independently functional and testable.

---

## Phase 4: User Story 2 - Derive and Authenticate Data With Managed Keys (Priority: P2)

**Goal**: Add managed `HMAC-SHA-256` and `P-256` ECDH plus `HKDF-SHA-256` derivation workflows through the CLI.

**Independent Test**: Generate or use allowed managed keys, run MAC/verify and derive workflows, and confirm wrong role, wrong usage, and oversized output are denied.

### Tests for User Story 2 ⚠️

- [x] T023 [P] [US2] Add protocol misuse-case tests for wrong-role, wrong-usage, malformed peer material, and oversized derive/MAC requests in [/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/mac_and_derive_denials.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/mac_and_derive_denials.rs)
- [x] T024 [P] [US2] Add protocol success-path tests for managed `HMAC-SHA-256` and `P-256` ECDH plus `HKDF-SHA-256` workflows in [/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/mac_and_derive_workflows.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/mac_and_derive_workflows.rs)
- [x] T025 [P] [US2] Add host client and CLI tests for `mac`, `verify-mac`, and `derive` commands in [/home/michael/src/embedded/rp_hsm/host_tools/tests/mac_and_derive_cli.rs](/home/michael/src/embedded/rp_hsm/host_tools/tests/mac_and_derive_cli.rs)

### Implementation for User Story 2

- [x] T026 [P] [US2] Implement managed MAC and derive profile metadata, usage rules, and output bounds in [/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs)
- [x] T027 [US2] Implement `HMAC-SHA-256` and `P-256` ECDH plus `HKDF-SHA-256` handlers in [/home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs)
- [x] T028 [P] [US2] Expose MAC and derive workflows through the host client in [/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs)
- [x] T029 [US2] Implement `rphsmtool` MAC and derive verbs, parsing, and result formatting in [/home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs) and [/home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs)
- [x] T030 [US2] Align derivation/authentication operator contracts and quickstart examples in [/home/michael/src/embedded/rp_hsm/README.md](/home/michael/src/embedded/rp_hsm/README.md), [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts/interoperability-and-derivation.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts/interoperability-and-derivation.md), and [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md)

**Checkpoint**: User Stories 1 and 2 should both be independently functional.

---

## Phase 5: User Story 3 - Export and Use Wrapped Key Material Safely (Priority: P3)

**Goal**: Add policy-bound wrapped export that complements the existing wrapped import workflow.

**Independent Test**: Mark an allowed key as exportable, export it, reimport it, and confirm non-exportable or wrong-state keys are denied cleanly.

### Tests for User Story 3 ⚠️

- [x] T031 [P] [US3] Add protocol misuse-case tests for non-exportable keys, wrong lifecycle state, and malformed wrapped-export/import material in [/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/wrapped_export_denials.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/wrapped_export_denials.rs)
- [x] T032 [P] [US3] Add protocol success-path tests for wrapped export plus coherent reimport in [/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/wrapped_export_workflows.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/wrapped_export_workflows.rs)
- [x] T033 [P] [US3] Add host client and CLI tests for `export-wrapped-key` and reimport workflows in [/home/michael/src/embedded/rp_hsm/host_tools/tests/wrapped_export_cli.rs](/home/michael/src/embedded/rp_hsm/host_tools/tests/wrapped_export_cli.rs)

### Implementation for User Story 3

- [x] T034 [P] [US3] Implement export-policy metadata and wrapped-export envelope rules in [/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs)
- [x] T035 [US3] Implement wrapped export handlers and policy enforcement in [/home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs)
- [x] T036 [P] [US3] Persist wrapped-export eligibility and related metadata in [/home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs](/home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs)
- [x] T037 [P] [US3] Expose wrapped export through the host client in [/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs)
- [x] T038 [US3] Implement `rphsmtool export-wrapped-key` and operator messaging for export denials in [/home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs) and [/home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs)
- [x] T039 [US3] Align wrapped export/import policy docs and examples in [/home/michael/src/embedded/rp_hsm/README.md](/home/michael/src/embedded/rp_hsm/README.md), [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts/wrapped-export-policy.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/contracts/wrapped-export-policy.md), and [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md)

**Checkpoint**: All user stories should now be independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Finish regression, engineering validation, and closeout work that spans the whole broadened suite.

- [x] T040 [P] Add bounded engineering probe coverage for sender interoperability, MAC, derive, and wrapped export in [/home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs)
- [x] T041 [P] Run and fix software validation for the broadened protocol and CLI surface via [/home/michael/src/embedded/rp_hsm/protocol/tests](/home/michael/src/embedded/rp_hsm/protocol/tests) and [/home/michael/src/embedded/rp_hsm/host_tools/tests](/home/michael/src/embedded/rp_hsm/host_tools/tests)
- [x] T042 [P] Update release-evidence and hardening references for the broadened crypto operator surface in [/home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-readiness-checklist.md](/home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-readiness-checklist.md) and [/home/michael/src/embedded/rp_hsm/SECURITY.md](/home/michael/src/embedded/rp_hsm/SECURITY.md)
- [x] T043 Run live `rphsmtool` hardware regression for discovery, sender interoperability, MAC, derive, wrapped export/import, and denial cases in [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md)
- [x] T044 Run bounded live firmware regression through [/home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs) using `cargo probe -- --port /dev/ttyACM0`
- [x] T045 Close out feature docs and task ledger in [/home/michael/src/embedded/rp_hsm/README.md](/home/michael/src/embedded/rp_hsm/README.md), [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/quickstart.md), and [/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/tasks.md](/home/michael/src/embedded/rp_hsm/specs/017-crypto-suite-expansion/tasks.md)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies, can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion and blocks all user stories
- **User Stories (Phases 3-5)**: Depend on Foundational completion
- **Polish (Phase 6)**: Depends on the desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational with no dependency on other stories
- **User Story 2 (P2)**: Can start after Foundational, but should land after User Story 1 so sender interoperability and derivation naming stay coherent in discovery/help text
- **User Story 3 (P3)**: Depends on Foundational and should land after User Story 2 because wrapped export must align with the final broadened profile and policy surface

### Within Each User Story

- Required misuse-case tests must be written and fail before implementation
- Shared state/codec changes must land before host wiring
- Host CLI help/output should follow the protocol behavior it exposes
- Documentation updates should reflect the actual supported profile names and returned `key_id` workflow

### Parallel Opportunities

- Setup tasks `T002-T004`
- Foundational tasks `T006-T008`, `T011-T014`
- US1 tests `T015-T017` and implementation tasks `T018`, `T020`
- US2 tests `T023-T025` and implementation tasks `T026`, `T028`
- US3 tests `T031-T033` and implementation tasks `T034`, `T036`, `T037`
- Polish tasks `T040-T042`

---

## Parallel Example: User Story 2

```bash
# Launch User Story 2 tests together:
Task: "Add misuse-case tests for MAC and derive denials in protocol/tests/protocol/mac_and_derive_denials.rs"
Task: "Add success-path tests for managed HMAC and derive workflows in protocol/tests/protocol/mac_and_derive_workflows.rs"
Task: "Add host CLI tests for mac, verify-mac, and derive in host_tools/tests/mac_and_derive_cli.rs"

# Launch independent implementation slices together:
Task: "Implement managed MAC and derive profile metadata in protocol/src/protocol/state.rs"
Task: "Expose MAC and derive through host_tools/src/client.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. **Stop and validate**: prove sender-side interoperability works through the published CLI/documentation

### Incremental Delivery

1. Deliver Setup + Foundational
2. Add User Story 1 and validate sender interoperability
3. Add User Story 2 and validate MAC/derive workflows
4. Add User Story 3 and validate wrapped export/import
5. Finish with live hardware regressions and closeout docs

### Parallel Team Strategy

1. One developer handles protocol state/codec/parser work
2. One developer handles firmware persistence and policy/export state
3. One developer handles `rphsmtool` client/CLI/docs
4. Merge at story checkpoints before hardware regression

---

## Notes

- [P] tasks = different files, no incomplete-task dependency
- [US#] labels map tasks to independently testable user stories
- This feature is not complete without bounded `rphsmtool` and `cargo probe` live regression
