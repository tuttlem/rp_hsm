# Research: Asymmetric Encryption Operations

## Decision: Ship one asymmetric-encryption profile first using X25519 + HKDF-SHA256 + ChaCha20-Poly1305

**Decision**: Implement a single first-shipping asymmetric-encryption profile
that uses an internal X25519 recipient private key, derives a shared secret from
an ephemeral sender public key, expands it with HKDF-SHA256, and protects the
plaintext with ChaCha20-Poly1305.

**Rationale**: The workspace already uses `chacha20poly1305` and `sha2`, so the
new cryptographic surface can stay narrow while adding one new asymmetric key
family that is purpose-built for encryption rather than overloading the
existing signing-key families. X25519 keeps key generation and public-material
handling compact, and a sealed-box style workflow fits the operator expectation
of “encrypt with the managed key, decrypt with the managed private key” without
claiming a full HPKE framework.

**Alternatives considered**:

- P-256 ECDH + AES-256-GCM: attractive because `p256` and `aes-gcm` already
  exist in the repo, but it would blur the separation between signing and
  encryption keys unless a second P-256 key kind were introduced at the same
  time.
- RSA OAEP: rejected because the workspace has no RSA implementation today and
  it would expand both dependency and performance risk too far for one feature.
- Full HPKE: rejected because it adds more protocol surface and suite
  negotiation than the current operator need requires.

## Decision: Model asymmetric decryption keys as a distinct managed key kind

**Decision**: Add a new managed key kind for asymmetric decryption keys instead
of reusing existing signing or symmetric key records.

**Rationale**: The repo already has centralized lifecycle and policy enforcement
for managed keys. A distinct key kind keeps usage rules explicit: asymmetric
decryption keys may be used for encrypt/decrypt under the chosen profile, but
must not be usable for signing or symmetric operations.

**Alternatives considered**:

- Reuse `p256` signing keys for encryption: rejected because it couples two
  distinct trust uses and makes policy denials less reviewable.
- Treat recipient keys as transient only: rejected because users expect managed
  HSM keys to persist and remain referenceable.

## Decision: Use a bounded ciphertext envelope with explicit profile fields

**Decision**: Define one bounded asymmetric ciphertext envelope that includes
the algorithm profile identifier, recipient key id, ephemeral public key, nonce,
ciphertext, and authentication tag.

**Rationale**: The device needs enough information to validate and decrypt the
payload without guessing. Making the envelope explicit also gives `rphsmtool`
one stable representation to pass through stdin/stdout and document in the
operator contracts.

**Alternatives considered**:

- Implicit envelope fields derived from raw ciphertext length: rejected because
  that would create ambiguous parse rules and harder-to-review denial behavior.
- Unbounded or streaming ciphertext frames: rejected because the current
  transport and buffer design is intentionally bounded.

## Decision: Keep encryption and decryption on the supported CLI surface

**Decision**: Add explicit `rphsmtool` operator verbs for `asym-encrypt` and
`asym-decrypt`, and extend `list-algorithms`, `generate-key`, and
`get-key-metadata` to cover the new profile.

**Rationale**: The product goal is an operator-usable HSM, not a
protocol-only capability. The existing CLI is already the supported user-facing
surface, so asymmetric encryption must arrive there directly rather than hiding
behind probe-only or low-level commands.

**Alternatives considered**:

- Put the capability in firmware only and defer CLI work: rejected because the
  user specifically called out `rphsmtool` and documentation updates.
- Require host users to construct envelope fields manually: rejected because
  that is an engineering workflow, not an operator workflow.

## Decision: Keep algorithm discovery explicit and deny unsupported profiles cleanly

**Decision**: Extend the algorithm-discovery surface so operators can see the
first shipping asymmetric-encryption profile and key capabilities, and deny any
unsupported or mismatched profile explicitly.

**Rationale**: The repo now has multiple crypto families. Operators need to know
which algorithms are available for generate, encrypt, decrypt, sign, and verify
without learning hidden implementation rules.

**Alternatives considered**:

- Infer capability from error messages only: rejected because that creates a
  poor operator surface and harder reviewability.
- Hide unsupported profiles in undocumented commands: rejected because explicit
  discovery is part of the requirement.
