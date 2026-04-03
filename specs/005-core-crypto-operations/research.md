# Research: Core Crypto Operations

## Decision 1: Keep the v1 crypto surface intentionally narrow

- Decision: Support four operation classes in v1:
  - managed `SignDetached` using active Ed25519 private keys
  - bounded `VerifyDetached` using caller-supplied public verification material
  - bounded `GenerateRandom`
  - `ImportWrappedKey` for controlled lifecycle workflows
- Rationale: This satisfies the product requirement for a useful core service
  surface without accidentally turning the firmware into a general-purpose
  cryptographic coprocessor. Managed signing is the core HSM value. Public
  verification is non-secret and integration-friendly. Random generation is a
  standard primitive. Wrapped import addresses lifecycle needs without enabling
  plaintext export.
- Alternatives considered:
  - Add decrypt/encrypt in v1: rejected because it widens the secret-bearing
    interface and requires more careful data-lifetime handling than this phase
    needs.
  - Add key agreement in v1: rejected because it introduces derived-secret
    lifecycle complexity before the key-policy model is mature enough.
  - Support every stored key algorithm immediately: rejected because current
    key-store metadata is broader than the reviewed cryptographic surface.

## Decision 2: Expose capability discovery publicly, but keep secret-affecting operations role-bound

- Decision:
  - `GetCryptoCapabilities` is public
  - `VerifyDetached` is public with strict size bounds
  - `GenerateRandom` requires an authenticated administrator or key-manager
    session
  - `SignDetached` and `ImportWrappedKey` require an authenticated key-manager
    session
- Rationale: Public capability discovery and public verification do not expose
  managed secrets and make host integration easier. Random generation, signing,
  and wrapped import consume scarce or secret-affecting resources and therefore
  need explicit authorization and abuse controls.
- Alternatives considered:
  - Make all crypto operations public: rejected because RNG abuse and wrapped
    import are not harmless public services.
  - Make verification authenticated only: rejected because it adds operational
    friction without a secrecy benefit.

## Decision 3: Use detached, bounded request shapes rather than streaming or opaque execution

- Decision:
  - `SignDetached` accepts a bounded message payload and returns a detached
    signature
  - `VerifyDetached` accepts a bounded message payload, algorithm identifier,
    detached signature, and public verification material
  - no streaming, chunked hashing, or multipart crypto in v1
- Rationale: The workspace already uses bounded `heapless` request handling.
  One-shot detached operations are easier to reason about, simpler to test, and
  safer to fail closed on malformed input or interrupted execution.
- Alternatives considered:
  - Stream large messages through the device: rejected because it complicates
    statefulness, replay handling, and buffer hygiene.
  - Sign pre-hashed digests only: rejected for v1 because algorithm-specific
    digest rules would complicate the API before the basic service surface is
    stable.

## Decision 4: Treat unsupported algorithm families as explicit denials, not hidden partial support

- Decision:
  - v1 managed signing uses Ed25519 only
  - v1 public verification supports Ed25519 and P-256 detached verification
  - stored `Aes256` and unsupported key classes remain non-cryptographic for
    this feature and must be denied explicitly
- Rationale: The existing key store already models multiple algorithm families,
  but feature safety is better served by a reviewed capability matrix than by
  assuming every algorithm enum is executable.
- Alternatives considered:
  - Implement P-256 signing in the same phase: rejected to keep signing,
    key-material handling, and validation simpler for the first secure cut.
  - Hide unsupported keys from crypto decisions: rejected because explicit
    denial is more reviewable than silent non-support.

## Decision 5: Wrapped key handling is import-only in v1

- Decision:
  - `ImportWrappedKey` is the only approved wrapped-key operation in v1
  - wrapped export is out of scope and denied
  - imported keys must land as non-exportable managed keys with explicit policy
    attributes
- Rationale: The product needs a lifecycle path for bringing approved material
  into the device, but wrapped export would create a much more dangerous secret
  exfiltration surface.
- Alternatives considered:
  - Support wrapped export for backup: rejected because it changes the product
    into a key movement device before audit, policy, and approval workflows are
    mature enough.
  - Omit wrapped handling entirely: rejected because the feature spec and
    roadmap require a controlled answer for lifecycle imports.

## Decision 6: RNG backend failure must fail closed, and request sizes must stay small

- Decision:
  - `GenerateRandom` returns between 1 and 64 bytes per request
  - if the firmware RNG backend is unavailable, unhealthy, or cannot satisfy the
    request deterministically, the command returns an explicit error and no
    output bytes
- Rationale: Small bounded responses fit the current framing and host probe
  model, and fail-closed behavior preserves the constitution’s deterministic and
  reviewable security boundary.
- Alternatives considered:
  - Allow arbitrarily large RNG requests: rejected because it encourages abuse
    and complicates bounded response handling.
  - Substitute deterministic pseudorandom output on backend failure: rejected
    because it violates fail-safe secrecy assumptions.

## Decision 7: Secret-bearing temporary buffers must be modeled explicitly

- Decision: The design will identify four secret-bearing transient classes:
  signing input buffers before dispatch completes, wrapped-import plaintext,
  intermediate private-key decoding buffers, and pre-frame RNG output buffers.
- Rationale: The constitution requires explicit lifetime and destruction points.
  Modeling those buffers now keeps tasks and code review aligned later.
- Alternatives considered:
  - Rely on ad hoc buffer clearing during implementation: rejected because it is
    easy to miss in a `no_std` firmware codebase.
