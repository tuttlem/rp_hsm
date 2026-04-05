# Research: Broadened Crypto Suite

## Decision: Keep sender interoperability on the existing `x25519-chacha20poly1305` recipient profile

**Decision**: Reuse the existing `x25519-chacha20poly1305` recipient-encryption
profile and add a documented sender-side workflow that uses exported public
material to produce compatible ciphertext envelopes outside the device.

**Rationale**: The repo already has a working managed recipient-encryption
profile and public-material export path. The missing value is not a new
recipient algorithm first; it is a supported interoperable sender workflow that
another system can use without reverse-engineering the envelope.

**Alternatives considered**:

- Add a second recipient-encryption family first: rejected because it widens the
  crypto suite without solving the actual interoperability gap.
- Make interoperability rely on undocumented external tooling: rejected because
  the user-facing CLI and docs must remain the supported operator surface.

## Decision: Add managed `HMAC-SHA-256` as the first authentication primitive

**Decision**: Introduce `HMAC-SHA-256` as the first managed MAC family with
explicit `generate`, `mac`, and `verify-mac` workflows.

**Rationale**: HMAC is widely useful for application integrity, request
authentication, and derived-secret confirmation. It broadens the HSM’s utility
without requiring immediate support for multiple hash/MAC families at once.

**Alternatives considered**:

- Add AES-CMAC first: rejected because HMAC is more broadly interoperable and
  easier for operators and integrators to validate externally.
- Add only a public hash helper first: rejected because authentication with a
  managed secret offers more real product value than unauthenticated hashing
  alone.

## Decision: Use `P-256` ECDH plus `HKDF-SHA-256` as the first managed derivation workflow

**Decision**: Add a managed `P-256` key-agreement path that derives a shared
secret on-device and immediately expands it with `HKDF-SHA-256` into bounded
output for operator-visible derivation workflows.

**Rationale**: The repo already supports `P-256` signing keys and verification.
Adding `P-256` key agreement broadens operator choice and creates a clean
managed derivation story without introducing a completely unrelated curve family
for the first derivation workflow.

**Alternatives considered**:

- Add raw ECDH output export: rejected because returning unstructured shared
  secrets is harder to justify and review than a bounded derived-output
  contract.
- Use X25519 for both recipient encryption and shared-secret derivation only:
  rejected because broadening choice is part of the feature goal and `P-256`
  gives a second widely used ecosystem path.

## Decision: Keep wrapped export policy-bound and coherent with the existing wrapped import surface

**Decision**: Add wrapped export only for explicitly exportable key classes and
keep it coherent with the existing wrapped import workflow, using one reviewed
envelope family instead of multiple export formats in the first release.

**Rationale**: The product needs controlled key movement, but wrapped export is
also one of the easiest places to accidentally punch a hole in HSM custody.
Keeping one reviewed export family and binding it to explicit policy preserves
the product boundary.

**Alternatives considered**:

- Plaintext key export for operator convenience: rejected because it violates
  the HSM custody model.
- Multiple wrapped-export algorithms in the first feature: rejected because
  policy, audit, and CLI complexity would grow faster than operator value.

## Decision: Keep the broadened suite attached to complete user workflows

**Decision**: Design the new crypto surface around complete workflows:
interoperable sender encryption, managed MAC/verify, managed derive, and
wrapped export/import, rather than around isolated primitive commands.

**Rationale**: The roadmap now explicitly prefers complete operator stories over
primitive sprawl. This keeps the CLI, policy matrix, and documentation
reviewable and prevents the product from becoming an incoherent crypto toolbox.

**Alternatives considered**:

- Expose every primitive independently and rely on users to compose them:
  rejected because it weakens the product boundary and operator usability.
- Keep the crypto suite narrow forever: rejected because the current user goal
  is to broaden options materially.
