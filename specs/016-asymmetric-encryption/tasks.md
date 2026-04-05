# Tasks: Asymmetric Encryption Operations

**Input**: Design documents from `/specs/016-asymmetric-encryption/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, and misuse-case tests are REQUIRED for this feature because it changes key handling, command surface, and firmware behavior.

**Regression**: This feature changes firmware and the supported operator surface, so it MUST include bounded `rphsmtool` and live hardware regression before closeout.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g. `US1`, `US2`, `US3`)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Add the new asymmetric-encryption dependencies and feature documentation scaffolding.

- [X] T001 Add `x25519-dalek` and `hkdf` dependencies to [protocol/Cargo.toml](/home/michael/src/embedded/rp_hsm/protocol/Cargo.toml)
- [X] T002 [P] Extend asymmetric-encryption feature notes and roadmap alignment in [README.md](/home/michael/src/embedded/rp_hsm/README.md) and [ROADMAP.md](/home/michael/src/embedded/rp_hsm/ROADMAP.md)
- [X] T003 [P] Add quick reference placeholders for the new CLI verbs in [host_tools/src/cli/args.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs)
- [X] T004 [P] Capture feature-specific threat assumptions and regression scope in [specs/016-asymmetric-encryption/quickstart.md](/home/michael/src/embedded/rp_hsm/specs/016-asymmetric-encryption/quickstart.md)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Define the shared protocol, state, persistence, and host abstractions that every user story depends on.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T005 Define new asymmetric-encryption command IDs, capability flags, and algorithm identifiers in [protocol/src/protocol/command.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs)
- [X] T006 [P] Define asymmetric key kind, algorithm profile, usage flags, and envelope structures in [protocol/src/protocol/state.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs)
- [X] T007 [P] Add codec request/response framing for generate/encrypt/decrypt/asymmetric metadata paths in [protocol/src/protocol/codec.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs)
- [X] T008 [P] Add typed host client request/response models for asymmetric encryption in [host_tools/src/client.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs)
- [X] T009 Implement fail-closed parser dispatch stubs and bounded error mapping for the new commands in [protocol/src/protocol/parser.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs)
- [X] T010 Define persistent storage handling for asymmetric decryption keys and related metadata in [firmware/src/persistence.rs](/home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs)
- [X] T011 [P] Wire restored asymmetric key state into the firmware boot path in [firmware/src/main.rs](/home/michael/src/embedded/rp_hsm/firmware/src/main.rs)
- [X] T012 [P] Add shared test fixtures for asymmetric key material and ciphertext envelopes in [protocol/tests/protocol/crypto_fixtures.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/crypto_fixtures.rs)
- [X] T013 [P] Add host-side CLI output helpers for asymmetric metadata and denials in [host_tools/src/cli/commands.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs)
- [X] T014 Document the operator-facing command surface and algorithm naming contract in [specs/016-asymmetric-encryption/contracts/asymmetric-encryption-commands.md](/home/michael/src/embedded/rp_hsm/specs/016-asymmetric-encryption/contracts/asymmetric-encryption-commands.md) and [specs/016-asymmetric-encryption/contracts/operator-cli-workflows.md](/home/michael/src/embedded/rp_hsm/specs/016-asymmetric-encryption/contracts/operator-cli-workflows.md)

**Checkpoint**: Foundation ready. User story implementation can now begin.

---

## Phase 3: User Story 1 - Encrypt to a Managed Recipient Key (Priority: P1) 🎯 MVP

**Goal**: Let a provisioned operator generate a managed asymmetric recipient key and encrypt plaintext to it through `rphsmtool`.

**Independent Test**: Provision the device, generate a `x25519-chacha20poly1305` key, encrypt a known plaintext through `rphsmtool`, and confirm a bounded ciphertext envelope is returned with valid metadata.

### Tests for User Story 1 ⚠️

- [X] T015 [P] [US1] Add protocol negative tests for unauthorized, wrong-state, and wrong-usage asymmetric key generation in [protocol/tests/protocol/asymmetric_key_generation.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/asymmetric_key_generation.rs)
- [X] T016 [P] [US1] Add protocol tests for successful managed recipient-key generation and envelope-producing encrypt in [protocol/tests/protocol/asymmetric_encryption.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/asymmetric_encryption.rs)
- [X] T017 [P] [US1] Add host client and CLI tests for `generate-key` plus `asym-encrypt` command parsing/output in [host_tools/tests/asymmetric_cli_workflows.rs](/home/michael/src/embedded/rp_hsm/host_tools/tests/asymmetric_cli_workflows.rs)

### Implementation for User Story 1

- [X] T018 [P] [US1] Implement managed asymmetric recipient-key generation, public-material export, and usage binding in [protocol/src/protocol/state.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs)
- [X] T019 [US1] Implement asymmetric key-generation and encrypt handlers in [protocol/src/protocol/parser.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs)
- [X] T020 [P] [US1] Persist generated asymmetric decryption keys and metadata in [firmware/src/persistence.rs](/home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs)
- [X] T021 [P] [US1] Expose `generate-key --algorithm x25519-chacha20poly1305` and `asym-encrypt` through [host_tools/src/cli/args.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs) and [host_tools/src/bin/rphsmtool.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs)
- [X] T022 [US1] Implement asymmetric encrypt request execution and ciphertext-envelope stdout handling in [host_tools/src/client.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs) and [host_tools/src/cli/commands.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs)
- [X] T023 [US1] Add public-material metadata exposure for managed recipient keys in [protocol/src/protocol/state.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs) and [host_tools/src/cli/commands.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs)

**Checkpoint**: User Story 1 should be independently functional and testable.

---

## Phase 4: User Story 2 - Decrypt with the Managed Private Key (Priority: P2)

**Goal**: Let a provisioned operator decrypt a valid asymmetric ciphertext envelope with the matching managed private key while malformed or mismatched inputs fail closed.

**Independent Test**: Encrypt a known plaintext to a managed asymmetric key, decrypt the returned ciphertext envelope through `rphsmtool`, confirm the original plaintext is recovered, and verify malformed or wrong-key envelopes are denied.

### Tests for User Story 2 ⚠️

- [X] T024 [P] [US2] Add protocol tests for successful decrypt round-trip and tampered-envelope denial in [protocol/tests/protocol/asymmetric_decryption.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/asymmetric_decryption.rs)
- [X] T025 [P] [US2] Add protocol tests for wrong-key, wrong-algorithm, revoked-key, and replay-sensitive decrypt denials in [protocol/tests/protocol/asymmetric_decryption.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/asymmetric_decryption.rs)
- [X] T026 [P] [US2] Add host-side CLI tests for `asym-decrypt` stdin/stdout behavior and bounded denial rendering in [host_tools/tests/asymmetric_cli_workflows.rs](/home/michael/src/embedded/rp_hsm/host_tools/tests/asymmetric_cli_workflows.rs)

### Implementation for User Story 2

- [X] T027 [P] [US2] Implement ciphertext-envelope validation, shared-secret derivation, HKDF expansion, and plaintext zeroization in [protocol/src/protocol/parser.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs)
- [X] T028 [US2] Implement decrypt policy checks for lifecycle, usage, replay, and key state in [protocol/src/protocol/state.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs)
- [X] T029 [P] [US2] Expose `asym-decrypt` through [host_tools/src/cli/args.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs) and [host_tools/src/bin/rphsmtool.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs)
- [X] T030 [US2] Implement host client decrypt execution and plaintext stdout handling in [host_tools/src/client.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs) and [host_tools/src/cli/commands.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs)
- [X] T031 [US2] Add audit/event coverage for asymmetric decrypt success and denial paths in [protocol/src/protocol/state.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs) and [protocol/tests/contract/asymmetric_encryption_vectors.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/contract/asymmetric_encryption_vectors.rs)

**Checkpoint**: User Stories 1 and 2 should both work independently.

---

## Phase 5: User Story 3 - Choose and Understand Asymmetric Encryption Algorithms (Priority: P3)

**Goal**: Let operators discover supported asymmetric-encryption profiles, generate usable keys with explicit algorithm selection, and understand bounded denials from the CLI.

**Independent Test**: List supported algorithms, generate a key with the supported profile, use it for encrypt/decrypt, and confirm unsupported profiles or mismatched usages are denied with readable errors.

### Tests for User Story 3 ⚠️

- [X] T032 [P] [US3] Add protocol contract tests for algorithm discovery, profile absence, and wrong-usage denials in [protocol/tests/contract/asymmetric_encryption_vectors.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/contract/asymmetric_encryption_vectors.rs)
- [X] T033 [P] [US3] Add host CLI tests for `list-algorithms`, `get-key-metadata`, and unsupported-profile messaging in [host_tools/tests/capability_exposure_rules.rs](/home/michael/src/embedded/rp_hsm/host_tools/tests/capability_exposure_rules.rs)
- [X] T034 [P] [US3] Add quickstart-oriented integration tests for algorithm discovery and key-id-driven workflows in [host_tools/tests/asymmetric_cli_workflows.rs](/home/michael/src/embedded/rp_hsm/host_tools/tests/asymmetric_cli_workflows.rs)

### Implementation for User Story 3

- [X] T035 [P] [US3] Extend algorithm discovery and metadata rendering for `x25519-chacha20poly1305` in [protocol/src/protocol/state.rs](/home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs) and [host_tools/src/cli/commands.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs)
- [X] T036 [US3] Update CLI help, usage text, and argument parsing for asymmetric-encryption workflows in [host_tools/src/cli/args.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs)
- [X] T037 [US3] Ensure host-side errors distinguish unsupported profile, wrong usage, and host transport failures in [host_tools/src/client.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/client.rs) and [host_tools/src/cli/output.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs)
- [X] T038 [US3] Align operator documentation and examples with returned `key_id` workflows in [README.md](/home/michael/src/embedded/rp_hsm/README.md) and [specs/016-asymmetric-encryption/quickstart.md](/home/michael/src/embedded/rp_hsm/specs/016-asymmetric-encryption/quickstart.md)

**Checkpoint**: All user stories should now be independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Finish regression, engineering validation, and closeout updates that span all stories.

- [X] T039 [P] Add `rphsmtool` end-to-end asymmetric-encryption probe coverage in [host_tools/src/bin/probe_protocol.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs)
- [X] T040 [P] Run and fix software validation for the new protocol and CLI surface via [protocol/tests/protocol/asymmetric_encryption.rs](/home/michael/src/embedded/rp_hsm/protocol/tests/protocol/asymmetric_encryption.rs) and [host_tools/tests/asymmetric_cli_workflows.rs](/home/michael/src/embedded/rp_hsm/host_tools/tests/asymmetric_cli_workflows.rs)
- [X] T041 [P] Update release-evidence and hardening references for the new operator surface in [specs/010-hardening-release-process/release-readiness-checklist.md](/home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-readiness-checklist.md) and [SECURITY.md](/home/michael/src/embedded/rp_hsm/SECURITY.md)
- [X] T042 Run live `rphsmtool` hardware regression for reset, provision, algorithm discovery, recipient-key generation, asymmetric encrypt/decrypt, metadata inspection, and denial cases in [specs/016-asymmetric-encryption/quickstart.md](/home/michael/src/embedded/rp_hsm/specs/016-asymmetric-encryption/quickstart.md)
- [X] T043 Run bounded live firmware regression through [host_tools/src/bin/probe_protocol.rs](/home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs) using `cargo probe -- --port /dev/ttyACM0`
- [X] T044 Close out feature docs and task ledger in [README.md](/home/michael/src/embedded/rp_hsm/README.md), [specs/016-asymmetric-encryption/quickstart.md](/home/michael/src/embedded/rp_hsm/specs/016-asymmetric-encryption/quickstart.md), and [specs/016-asymmetric-encryption/tasks.md](/home/michael/src/embedded/rp_hsm/specs/016-asymmetric-encryption/tasks.md)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies, can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion and blocks all user stories
- **User Stories (Phases 3-5)**: Depend on Foundational completion
- **Polish (Phase 6)**: Depends on the desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational with no dependency on other stories
- **User Story 2 (P2)**: Depends on User Story 1 because decrypt requires the new key and envelope path
- **User Story 3 (P3)**: Can start after Foundational but should land after the main encrypt/decrypt workflow so discovery reflects the final surface

### Within Each User Story

- Required misuse-case tests must be written and fail before implementation
- Shared state/codec work must land before host wiring
- Host CLI help/output should follow the protocol behavior it exposes
- Documentation updates should reflect the actual implemented algorithm names and returned `key_id` flow

### Parallel Opportunities

- Setup tasks `T002-T004`
- Foundational tasks `T006-T008`, `T011-T014`
- US1 tests `T015-T017` and implementation tasks `T018`, `T020`, `T021`
- US2 tests `T024-T026` and implementation tasks `T027`, `T029`
- US3 tests `T032-T034` and implementation task `T035`
- Polish tasks `T039-T041`

---

## Parallel Example: User Story 1

```bash
# Launch User Story 1 tests together:
Task: "Add protocol negative tests for asymmetric key generation in protocol/tests/protocol/asymmetric_key_generation.rs"
Task: "Add protocol encrypt success-path tests in protocol/tests/protocol/asymmetric_encryption.rs"
Task: "Add host CLI tests for generate-key and asym-encrypt in host_tools/tests/asymmetric_cli_workflows.rs"

# Launch independent implementation slices together:
Task: "Implement managed asymmetric recipient-key generation in protocol/src/protocol/state.rs"
Task: "Persist generated asymmetric keys in firmware/src/persistence.rs"
Task: "Expose generate-key/asym-encrypt CLI arguments in host_tools/src/cli/args.rs and host_tools/src/bin/rphsmtool.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. **Stop and validate**: generate a managed recipient key and encrypt plaintext through `rphsmtool`

### Incremental Delivery

1. Deliver Setup + Foundational
2. Add User Story 1 and validate encrypt path
3. Add User Story 2 and validate full encrypt/decrypt round trip plus denial paths
4. Add User Story 3 and validate discovery, help text, and bounded UX
5. Finish with live hardware regressions and closeout docs

### Parallel Team Strategy

1. One developer handles protocol state/codec/parser work
2. One developer handles firmware persistence/wiring
3. One developer handles `rphsmtool` client/CLI/docs
4. Merge at the story checkpoints before hardware regression

---

## Notes

- [P] tasks = different files, no incomplete-task dependency
- [US#] labels map tasks to independently testable user stories
- This feature is not complete without live `rphsmtool` regression and bounded `cargo probe` validation
