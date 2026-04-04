# Tasks: Basic HSM Operations

**Input**: Design documents from `/specs/015-basic-hsm-ops/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, misuse-case, and live regression tests are REQUIRED for this feature because it adds new key-generation, encrypt/decrypt, and signing trust-boundary behavior.

**Regression**: This feature changes firmware, persistent state, authorization-sensitive crypto paths, and the supported host/user surface, so bounded regression-validation tasks for `rphsmtool` and live hardware behavior are REQUIRED before closeout.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (`US1`, `US2`, `US3`)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Capture the minimum HSM operator surface, reserve the design surfaces, and align repo guidance before implementation begins.

- [ ] T001 Capture the `015-basic-hsm-ops` scope, first-shipping algorithm set, and operator workflow boundary in /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/contracts/
- [ ] T002 [P] Add README and roadmap notes for generated keys, symmetric encrypt/decrypt, and algorithm discovery expectations in /home/michael/src/embedded/rp_hsm/README.md and /home/michael/src/embedded/rp_hsm/ROADMAP.md
- [ ] T003 [P] Reserve repository security guidance for generated-key handling, plaintext exposure rules, and crypto regression requirements in /home/michael/src/embedded/rp_hsm/SECURITY.md and /home/michael/src/embedded/rp_hsm/README.md
- [ ] T004 [P] Align the feature quickstart with the provision, algorithm discovery, symmetric round-trip, and signing round-trip flows in /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/quickstart.md

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Add the shared protocol, state, persistence, and CLI building blocks needed before any user story can complete independently.

**⚠️ CRITICAL**: No user story work should begin until this phase is complete.

- [ ] T005 Define new protocol command IDs, command metadata, and privilege/state requirements for algorithm listing and generated-key crypto operations in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [ ] T006 [P] Add codec support for algorithm-listing, key-generation, symmetric encrypt/decrypt, and signing payloads and responses in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [ ] T007 [P] Extend protocol state types for algorithm profiles, generated-key metadata, ciphertext records, and detached-signature records in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [ ] T008 [P] Extend firmware persistence encoding and decoding for generated symmetric and asymmetric key material plus metadata revisions in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs
- [ ] T009 Add parser dispatch stubs and fail-closed denial plumbing for the new crypto command family in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [ ] T010 [P] Add host client request/response types for algorithm listing, key generation, symmetric encrypt/decrypt, and generated-key signing in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs
- [ ] T011 [P] Add CLI command specifications and argument parsing for `list-algorithms`, `generate-key`, `sym-encrypt`, and `sym-decrypt` in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs
- [ ] T012 [P] Add CLI output helpers for algorithm profiles, generated-key creation results, and bounded crypto denials in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/output.rs
- [ ] T013 Document the first-shipping algorithm set, generated-key model, and operator CLI contract in /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/contracts/key-generation-and-algorithms.md and /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/contracts/operator-cli-workflows.md
- [ ] T014 Record the bounded secret-handling, algorithm-selection, and generated-key persistence decisions in /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/research.md and /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/data-model.md

**Checkpoint**: Shared protocol, persistence, and CLI scaffolding is ready for user-story work.

---

## Phase 3: User Story 1 - Generate and Use Symmetric Keys (Priority: P1) 🎯 MVP

**Goal**: Let an authorized operator generate a symmetric key internally, encrypt plaintext, and decrypt the resulting ciphertext back to the original plaintext without exporting the key.

**Independent Test**: Provision the device, generate a `chacha20poly1305` key through `rphsmtool`, encrypt a known plaintext, decrypt the ciphertext, and confirm the plaintext matches exactly while malformed or wrong-usage inputs are denied.

### Tests for User Story 1 ⚠️

- [ ] T015 [P] [US1] Add protocol tests for symmetric key generation, encrypt/decrypt success, and malformed symmetric payload denials in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs
- [ ] T016 [P] [US1] Add contract tests for wrong algorithm, wrong key type, revoked key, and wrong lifecycle-state denials for symmetric operations in /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [ ] T017 [P] [US1] Add host-tools tests for `list-algorithms`, `generate-key`, `sym-encrypt`, and `sym-decrypt` parsing and output behavior in /home/michael/src/embedded/rp_hsm/host_tools/tests/

### Implementation for User Story 1

- [ ] T018 [P] [US1] Implement generated symmetric-key storage, metadata origin, and usage-mask handling in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [ ] T019 [US1] Implement parser handlers for `list-algorithms`, symmetric `generate-key`, `sym-encrypt`, and `sym-decrypt` in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [ ] T020 [US1] Wire firmware persistence save/restore for generated symmetric keys and crypto-state revisions in /home/michael/src/embedded/rp_hsm/firmware/src/main.rs and /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs
- [ ] T021 [P] [US1] Implement host client methods for listing algorithms, generating symmetric keys, encrypting, and decrypting in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs
- [ ] T022 [US1] Implement `rphsmtool list-algorithms`, `generate-key`, `sym-encrypt`, and `sym-decrypt` command execution in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/bin/rphsmtool.rs
- [ ] T023 [US1] Align the symmetric round-trip workflow and denial examples in /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/quickstart.md and /home/michael/src/embedded/rp_hsm/README.md

**Checkpoint**: Operators can complete a symmetric generate/encrypt/decrypt round trip through the supported CLI.

---

## Phase 4: User Story 2 - Generate and Use Asymmetric Keys (Priority: P2)

**Goal**: Let an authorized operator generate an internal `Ed25519` signing keypair, sign a message, and verify the signature with matching public material.

**Independent Test**: Provision the device, generate an `ed25519` signing key through `rphsmtool`, sign a known message, verify it successfully, and confirm a modified message or wrong algorithm fails verification.

### Tests for User Story 2 ⚠️

- [ ] T024 [P] [US2] Add protocol tests for generated `ed25519` keypair creation, detached signing success, and signing denials from wrong key usage or wrong lifecycle state in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs
- [ ] T025 [P] [US2] Add contract tests for verification mismatch, malformed signature payloads, and wrong-algorithm denials in /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [ ] T026 [P] [US2] Add host-tools tests for generated-key signing, public verification inputs, and readable denial output in /home/michael/src/embedded/rp_hsm/host_tools/tests/

### Implementation for User Story 2

- [ ] T027 [P] [US2] Extend generated-key state and metadata handling for internal `Ed25519` keypairs and public-material references in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [ ] T028 [US2] Implement parser handlers for asymmetric `generate-key` and generated-key detached signing in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [ ] T029 [US2] Extend codec and persistence support for generated signing-key metadata and bounded public verification references in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs and /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs
- [ ] T030 [P] [US2] Implement host client support for asymmetric key generation and generated-key signing result handling in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs
- [ ] T031 [US2] Extend `rphsmtool generate-key`, `sign`, `verify`, and `get-key-metadata` workflows for generated signing keys in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs
- [ ] T032 [US2] Align the signing round-trip, metadata lookup, and verification denial walkthroughs in /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/contracts/symmetric-and-signing-operations.md and /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/quickstart.md

**Checkpoint**: Operators can generate a signing key internally and complete a detached sign/verify round trip through the CLI.

---

## Phase 5: User Story 3 - Choose Algorithms and Operate Through the CLI (Priority: P3)

**Goal**: Let operators discover supported algorithms, choose allowed algorithms and usage flags when generating or using keys, and receive bounded denials for unsupported choices.

**Independent Test**: Provision the device, list algorithms, generate keys for allowed algorithms, perform the supported workflows, then attempt unsupported algorithm or wrong-usage operations and confirm bounded readable denials.

### Tests for User Story 3 ⚠️

- [ ] T033 [P] [US3] Add protocol tests for algorithm-discovery payloads, unsupported algorithm denials, and wrong-usage denials across symmetric and signing flows in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs
- [ ] T034 [P] [US3] Add host-tools tests for CLI algorithm parsing, algorithm-list rendering, and denial wording for unsupported choices in /home/michael/src/embedded/rp_hsm/host_tools/tests/
- [ ] T035 [P] [US3] Add probe regression coverage for algorithm discovery, generated-key workflows, and unsupported-choice denial checks in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 3

- [ ] T036 [P] [US3] Finalize protocol algorithm-profile definitions, allowed-operation flags, and verification-only `p256` exposure in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [ ] T037 [US3] Finalize CLI parsing and UX for `--algorithm`, `--usage`, and algorithm-list output in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs and /home/michael/src/embedded/rp_hsm/host_tools/src/cli/commands.rs
- [ ] T038 [US3] Document the supported algorithm set, unsupported-choice behavior, and CLI operator expectations in /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/contracts/key-generation-and-algorithms.md, /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/contracts/operator-cli-workflows.md, and /home/michael/src/embedded/rp_hsm/README.md
- [ ] T039 [US3] Align `rphsmtool` help text and examples for `list-algorithms`, `generate-key`, `sym-encrypt`, and `sym-decrypt` in /home/michael/src/embedded/rp_hsm/host_tools/src/cli/args.rs and /home/michael/src/embedded/rp_hsm/README.md

**Checkpoint**: Operators can discover and choose supported algorithms explicitly, and unsupported choices fail closed with readable denials.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final integration, regression, and documentation alignment across all stories.

- [ ] T040 [P] Add release-readiness notes for the new crypto surface and regression expectations in /home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/examples/ and /home/michael/src/embedded/rp_hsm/README.md
- [ ] T041 [P] Clean up duplicated algorithm-set, generated-key, and denial wording across /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/contracts/, /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/quickstart.md, and /home/michael/src/embedded/rp_hsm/README.md
- [ ] T042 Run software validation for protocol, firmware, and host tools covering the new crypto paths and record the results in /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/quickstart.md
- [ ] T043 Run the live `rphsmtool` hardware regression for reset, provision, list-algorithms, symmetric round-trip, signing round-trip, denial checks, and status/key-metadata verification in /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/quickstart.md
- [ ] T044 Run `cargo probe -- --port /dev/ttyACM0` as the firmware-affecting regression gate and align any drift in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs and /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/quickstart.md
- [ ] T045 Record completion status and final consistency cleanup in /home/michael/src/embedded/rp_hsm/specs/015-basic-hsm-ops/tasks.md

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies, can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion and blocks all user stories
- **User Story phases (Phases 3-5)**: Depend on Foundational completion
- **Polish (Phase 6)**: Depends on the desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Starts after Foundational completion and delivers the MVP operator-complete symmetric crypto path
- **User Story 2 (P2)**: Starts after Foundational completion and depends on the shared generated-key model from Phase 2
- **User Story 3 (P3)**: Starts after Foundational completion and depends on the shared algorithm-profile, CLI, and generated-key model from Phase 2

### Within Each User Story

- Security and misuse-case tests should be written before implementation is treated as complete
- Protocol/state/codec support before firmware persistence and host integration
- Host client support before CLI wiring
- CLI behavior before quickstart and README signoff
- Story regression proof before moving to final closeout

### Parallel Opportunities

- Setup tasks `T002-T004`
- Foundational tasks `T006-T008` and `T010-T014`
- US1 tests `T015-T017` and implementation tasks `T018`, `T021`
- US2 tests `T024-T026` and implementation tasks `T027`, `T030`
- US3 tests `T033-T035` and implementation tasks `T036`, `T038`
- Polish tasks `T040-T041`

---

## Parallel Example: User Story 1

```bash
# Launch US1 test tasks together:
Task: "Add protocol tests for symmetric key generation, encrypt/decrypt success, and malformed symmetric payload denials in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs"
Task: "Add contract tests for wrong algorithm, wrong key type, revoked key, and wrong lifecycle-state denials for symmetric operations in /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs"
Task: "Add host-tools tests for list-algorithms, generate-key, sym-encrypt, and sym-decrypt parsing and output behavior in /home/michael/src/embedded/rp_hsm/host_tools/tests/"

# Launch US1 implementation tasks together:
Task: "Implement generated symmetric-key storage, metadata origin, and usage-mask handling in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs"
Task: "Implement host client methods for listing algorithms, generating symmetric keys, encrypting, and decrypting in /home/michael/src/embedded/rp_hsm/host_tools/src/client.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. Validate the symmetric generate/encrypt/decrypt workflow independently

### Incremental Delivery

1. Setup + Foundational
2. User Story 1: symmetric key generation and encrypt/decrypt
3. User Story 2: internal signing-key generation and sign/verify
4. User Story 3: explicit algorithm discovery and operator-facing algorithm selection
5. Polish and regression closeout

### Suggested MVP Scope

- Phase 1
- Phase 2
- Phase 3 only

---

## Notes

- [P] tasks are parallelizable because they touch separate files or separate layers
- Each user story remains independently testable against its own acceptance criteria
- This feature is not complete until the documented `rphsmtool` surface and the live firmware regression both pass on hardware
