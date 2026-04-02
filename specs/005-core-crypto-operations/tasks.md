# Tasks: Core Crypto Operations

**Input**: Design documents from `/specs/005-core-crypto-operations/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Security, malformed-input, misuse-case, contract, and hardware-probe tests are required for this feature because it changes the cryptographic command surface, secret-handling paths, and authorization boundaries.

**Organization**: Tasks are grouped by user story so each story can be implemented and tested independently.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (`US1`, `US2`, `US3`)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Capture the feature boundary and reserve the documentation and probe surfaces.

- [X] T001 Capture the crypto command-set scope, excluded operations, and size-limit notes in /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/contracts/
- [X] T002 [P] Add README notes for crypto-surface validation and developer-mode probe expectations in /home/michael/src/embedded/rp_hsm/README.md
- [X] T003 [P] Reserve protocol test modules for crypto operation scenarios in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [X] T004 [P] Reserve host probe sections for crypto operation coverage in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared crypto infrastructure that must exist before any story can be implemented.

**⚠️ CRITICAL**: No user story work should begin until this phase is complete.

- [X] T005 Define crypto command ids, operation metadata, and developer-mode exclusions in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs
- [X] T006 [P] Extend request and response codecs for capability discovery, signing, verification, RNG, and wrapped import in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T007 [P] Add crypto operation request, policy, and secret-buffer tracking structures to /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T008 [P] Add bounded secret-clearing helpers and crypto-specific validation markers to /home/michael/src/embedded/rp_hsm/protocol/src/protocol/mod.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T009 Implement protocol-engine storage for crypto capability state, backend health flags, and firmware-action plumbing in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T010 [P] Extend persisted state structures for crypto-policy baselines and wrapped-import bookkeeping in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs
- [X] T011 [P] Wire crypto state restore, save, and rollback behavior into /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T012 [P] Add foundational contract coverage for capability discovery, bounded response shapes, and redaction in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/crypto_command_vectors.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract/crypto_redaction_vectors.rs
- [X] T013 [P] Add foundational protocol coverage for malformed crypto requests and unsupported algorithm denial in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/crypto_surface_validation.rs
- [X] T014 Document secret-buffer handling, developer-mode exclusions, and release expectations in /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/quickstart.md and /home/michael/src/embedded/rp_hsm/README.md

**Checkpoint**: Core crypto plumbing, persistence hooks, and validation scaffolding are ready for story work.

---

## Phase 3: User Story 1 - Controlled Use of Managed Keys (Priority: P1) 🎯 MVP

**Goal**: Allow authorized clients to use managed keys for approved operations without exposing secret key material.

**Independent Test**: Authenticate as key manager, run `SignDetached` with an allowed Ed25519 key, then retry with incompatible lifecycle state or usage and confirm explicit denial with no key exposure.

### Tests for User Story 1 ⚠️

- [X] T015 [P] [US1] Add protocol tests for managed signing success and incompatible-key denial in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/managed_signing.rs
- [X] T016 [P] [US1] Add contract tests for `SignDetached` request and response bounds in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/crypto_command_vectors.rs
- [X] T017 [P] [US1] Add host probe assertions for authorized signing and denied incompatible-key use in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 1

- [X] T018 [P] [US1] Implement managed-signing policy checks and key capability evaluation in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T019 [P] [US1] Implement `SignDetached` payload decoding and detached-signature encoding in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T020 [US1] Implement `SignDetached` dispatch, key lookup, and fail-closed execution in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T021 [US1] Enforce secret-buffer clearing for signing inputs and intermediate key material in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/mod.rs
- [X] T022 [US1] Integrate managed-signing backend selection and denial on unsupported algorithms in /home/michael/src/embedded/rp_hsm/firmware/src/main.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T023 [US1] Update signing command expectations and denial cases in /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/contracts/crypto-commands.md and /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/quickstart.md

**Checkpoint**: User Story 1 should now be independently functional and testable.

---

## Phase 4: User Story 2 - Trusted Verification and Randomness (Priority: P2)

**Goal**: Provide safe public verification and bounded random generation without widening secret exposure.

**Independent Test**: Run public `VerifyDetached` for true and false cases, then run authorized `GenerateRandom` at the maximum size and confirm unauthorized or zero-length RNG requests are denied.

### Tests for User Story 2 ⚠️

- [X] T024 [P] [US2] Add protocol tests for detached verification success, false results, and malformed verification requests in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/public_verification.rs
- [X] T025 [P] [US2] Add protocol tests for bounded random generation, unauthorized access, and backend-failure denial in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/random_generation.rs
- [X] T026 [P] [US2] Add contract tests for `GetCryptoCapabilities`, `VerifyDetached`, and `GenerateRandom` in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/crypto_command_vectors.rs
- [X] T027 [P] [US2] Add host probe steps for verification and random-generation flows in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 2

- [X] T028 [P] [US2] Implement capability-discovery state and supported-operation flags in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T029 [P] [US2] Implement `GetCryptoCapabilities`, `VerifyDetached`, and `GenerateRandom` codec support in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T030 [US2] Implement public verification dispatch and algorithm-specific length validation in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T031 [US2] Implement bounded RNG execution, authorization checks, and fail-closed backend error handling in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs and /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T032 [US2] Enforce redaction and non-secret result rules for verification and RNG responses in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs and /home/michael/src/embedded/rp_hsm/firmware/src/logging.rs
- [X] T033 [US2] Update public-service expectations and size-limit documentation in /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/contracts/crypto-commands.md, /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/contracts/operation-policy-matrix.md, and /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/quickstart.md

**Checkpoint**: User Stories 1 and 2 should both work independently.

---

## Phase 5: User Story 3 - Restricted Handling of High-Risk Operations (Priority: P3)

**Goal**: Bound wrapped-key import and explicitly deny excluded or policy-incompatible high-risk operations.

**Independent Test**: Authenticate as key manager, perform one approved `ImportWrappedKey`, then retry with malformed envelope, forbidden export policy, unsupported algorithm, and excluded reserved commands and confirm fail-closed denial.

### Tests for User Story 3 ⚠️

- [X] T034 [P] [US3] Add protocol tests for wrapped-key import success, malformed-envelope denial, and forbidden destination-policy denial in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/wrapped_import.rs
- [X] T035 [P] [US3] Add protocol tests for excluded high-risk command denial and interrupted-operation cleanup in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/high_risk_denials.rs
- [X] T036 [P] [US3] Add contract tests for `ImportWrappedKey` and excluded-command behavior in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/crypto_command_vectors.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract/crypto_redaction_vectors.rs
- [X] T037 [P] [US3] Add host probe steps for wrapped import, forbidden exportability, and excluded-operation denials in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs

### Implementation for User Story 3

- [X] T038 [P] [US3] Implement wrapped-import envelope validation, destination-policy checks, and operation-policy matrix enforcement in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs
- [X] T039 [P] [US3] Implement `ImportWrappedKey` codec support and bounded non-secret result encoding in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T040 [US3] Implement `ImportWrappedKey` dispatch, unwrap failure handling, and no-partial-state guarantees in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T041 [US3] Integrate wrapped-import persistence, rollback on commit failure, and secret-buffer clearing in /home/michael/src/embedded/rp_hsm/firmware/src/persistence.rs and /home/michael/src/embedded/rp_hsm/firmware/src/main.rs
- [X] T042 [US3] Enforce explicit denial for excluded export, decrypt, encrypt, and key-agreement command classes in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/command.rs and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs
- [X] T043 [US3] Update wrapped-import control rules and excluded-operation notes in /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/contracts/crypto-commands.md, /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/contracts/operation-policy-matrix.md, and /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/quickstart.md

**Checkpoint**: All user stories should now be independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final integration, cleanup, and end-to-end validation across the crypto surface.

- [X] T044 [P] Add end-to-end crypto regression coverage across /home/michael/src/embedded/rp_hsm/protocol/tests/protocol.rs and /home/michael/src/embedded/rp_hsm/protocol/tests/contract.rs
- [X] T045 [P] Clean up crypto helper boundaries, dead code, and duplicated limit constants in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs, /home/michael/src/embedded/rp_hsm/protocol/src/protocol/parser.rs, and /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs
- [X] T046 Update operator workflow and cargo command notes for crypto validation in /home/michael/src/embedded/rp_hsm/README.md
- [X] T047 Run the quickstart validation sequence and align any drift in /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/quickstart.md
- [X] T048 Run workspace validation commands and record completion status in /home/michael/src/embedded/rp_hsm/specs/005-core-crypto-operations/tasks.md

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies, can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion and blocks all story work
- **User Story phases (Phases 3-5)**: Depend on Foundational completion
- **Polish (Phase 6)**: Depends on the desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Starts after Foundational completion and delivers the MVP
- **User Story 2 (P2)**: Starts after Foundational completion and can integrate with shared crypto plumbing without depending on US1 completion
- **User Story 3 (P3)**: Starts after Foundational completion and depends only on the shared crypto and key-store foundations, not on prior story completion

### Within Each User Story

- Required tests must exist and fail before implementation is considered complete
- State and policy definitions before dispatch logic
- Codecs before end-to-end handler wiring
- Secret-buffer clearing before final probe and documentation sign-off

### Parallel Opportunities

- Setup tasks `T002-T004`
- Foundational tasks `T006-T008` and `T010-T013`
- US1 tests `T015-T017` and implementation pair `T018-T019`
- US2 tests `T024-T027` and implementation pair `T028-T029`
- US3 tests `T034-T037` and implementation pair `T038-T039`
- Polish tasks `T044-T046`

---

## Parallel Example: User Story 1

```bash
# Launch US1 validation tasks together:
Task: "Add protocol tests for managed signing success and incompatible-key denial in /home/michael/src/embedded/rp_hsm/protocol/tests/protocol/managed_signing.rs"
Task: "Add contract tests for SignDetached request and response bounds in /home/michael/src/embedded/rp_hsm/protocol/tests/contract/crypto_command_vectors.rs"
Task: "Add host probe assertions for authorized signing and denied incompatible-key use in /home/michael/src/embedded/rp_hsm/host_tools/src/bin/probe_protocol.rs"

# Launch US1 implementation tasks together:
Task: "Implement managed-signing policy checks and key capability evaluation in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/state.rs"
Task: "Implement SignDetached payload decoding and detached-signature encoding in /home/michael/src/embedded/rp_hsm/protocol/src/protocol/codec.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. Validate managed signing independently before moving on

### Incremental Delivery

1. Setup + Foundational
2. User Story 1: managed signing
3. User Story 2: public verification and bounded RNG
4. User Story 3: wrapped import and explicit high-risk denials
5. Polish and hardware validation

### Suggested MVP Scope

- Phase 1
- Phase 2
- Phase 3 only

---

## Notes

- [P] tasks are parallelizable because they touch separate files or independent test surfaces
- Each user story remains independently testable against its own acceptance criteria
- Required misuse-case and malformed-input tests are included because this feature changes a cryptographic trust boundary
