# Research: Basic HSM Operations

## Decision: Ship one symmetric authenticated-encryption algorithm first and make selection explicit anyway

**Decision**: Use `ChaCha20-Poly1305` as the first shipping symmetric
encrypt/decrypt algorithm in `015`, and require explicit algorithm selection
through the protocol and CLI even when only one symmetric algorithm is currently
enabled.

**Rationale**: The `protocol` crate already depends on `chacha20poly1305`, so
this feature can land a real authenticated-encryption workflow without adding a
new primitive family at the same time as key generation, metadata, and CLI
surface changes. Explicit selection and discovery still matter because they set
the operator-facing contract correctly for future algorithms.

**Alternatives considered**:

- `AES-256-GCM` first: aligned with the longer-term roadmap, but would expand
  implementation risk and dependency surface at the same time as the first
  end-to-end symmetric workflow.
- Plain unauthenticated symmetric encryption: rejected because it would create a
  misleading and insecure HSM data path.

## Decision: Restrict asymmetric key generation in this feature to `Ed25519` signing keys

**Decision**: Generate device-internal `Ed25519` keypairs for detached signing
in `015`; keep `P-256` verification-only support as a public verification path,
not a generated private-key path in this feature.

**Rationale**: `Ed25519` is already the existing signing path in the protocol
crate, so internal key generation can extend a real, already-reviewed signing
surface instead of creating a new asymmetric family and signing implementation
at the same time. This keeps the asymmetric operator workflow credible without
pretending public-key encryption or key agreement are done.

**Alternatives considered**:

- Generate `P-256` signing keys too: useful, but it broadens both crypto and key
  lifecycle scope more than needed for the minimum operator-complete surface.
- Public-key encryption first: rejected because the current repo has no
  reviewed asymmetric encryption surface to extend.

## Decision: Model generated keys as first-class persistent key records with explicit origin and usage

**Decision**: Persist generated symmetric keys and generated `Ed25519` private
keys as normal key-store records with explicit `origin=device-generated`,
algorithm, usage flags, export policy, lifecycle state, and revision metadata.

**Rationale**: The repo already has persistent key metadata and lifecycle rules.
Making generated keys use the same reviewable record model avoids inventing a
shadow crypto store and keeps policy enforcement centralized.

**Alternatives considered**:

- Ephemeral generated keys only: rejected because it does not satisfy the
  operator expectation of managed HSM keys.
- Separate crypto-only store: rejected because it would fragment lifecycle and
  policy handling.

## Decision: Add dedicated operator verbs instead of overloading existing low-level commands

**Decision**: Add explicit `rphsmtool` operator verbs for `list-algorithms`,
`generate-key`, `sym-encrypt`, `sym-decrypt`, and reuse `sign`/`verify` with
the new generated-key flow.

**Rationale**: The operator surface needs to reflect user tasks directly. Raw
frame construction or test-only pathways would repeat the same mistake the CLI
was created to eliminate.

**Alternatives considered**:

- Require users to compose low-level commands manually: rejected because that is
  an engineering surface, not an operator surface.
- Keep generation internal to tests only: rejected because the feature’s goal is
  end-user completeness.

## Decision: Bound crypto request sizes and record only non-secret evidence

**Decision**: Keep bounded request sizes for plaintext, ciphertext, nonce/tag,
signature, and key identifiers, and ensure audit/CLI outputs report algorithm,
key ID, and result without logging plaintext or generated secret material.

**Rationale**: This is required by the constitution and fits the existing
bounded-buffer design used throughout the repo.

**Alternatives considered**:

- Allow unbounded streaming in this feature: rejected because it would require a
  broader transport and buffering design.
- Log raw crypto inputs for troubleshooting: rejected because it would violate
  secret-handling rules.
