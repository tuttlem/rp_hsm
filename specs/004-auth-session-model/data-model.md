# Data Model: Authentication and Session Model

## Entity: CredentialRecord

- Fields:
  - `record_version`: schema version for credential decoding
  - `role`: reviewed role identifier
  - `credential_kind`: verifier format identifier for the role
  - `verifier_bytes`: bounded verifier data, never plaintext reusable secrets
  - `salt_or_binding`: bounded role-specific salt or device binding data
  - `policy_revision`: revision of the role policy that owns this credential
  - `enabled`: whether the role credential may establish new sessions
  - `integrity_tag`: bounded integrity check over the persisted record
- Relationships:
  - Owns one `RolePolicy`
  - Can establish one `SessionRecord` at a time in v1
- Validation rules:
  - `role` must map to a reviewed command authority class
  - `verifier_bytes` and `salt_or_binding` must fit fixed bounded lengths
  - unsupported `credential_kind` values are rejected
  - disabled credentials cannot create new sessions
  - plaintext or raw reusable credential material is never stored

## Entity: RolePolicy

- Fields:
  - `role`: `bootstrap`, `administrator`, `recovery`, or `key_manager`
  - `allowed_commands`: bounded set or bitmask of authorized command ids or
    families
  - `session_timeout_ticks`: bounded inactivity or lifetime limit
  - `freshness_window`: maximum accepted request-counter skew
  - `max_failures`: threshold before protective action
  - `lockout_ticks`: lockout or backoff interval after threshold breach
  - `requires_lifecycle_states`: device states in which this role may
    authenticate
- Validation rules:
  - every privileged command must map to exactly one required minimum role
  - public commands are not represented as authenticated role policy
  - roles cannot authorize commands outside their reviewed scope

## Entity: AuthenticationChallenge

- Fields:
  - `challenge_id`: unique bounded identifier for the in-flight auth attempt
  - `requested_role`: role being requested
  - `nonce`: bounded random or pseudo-random challenge bytes
  - `issued_at_revision`: device revision at issuance
  - `expires_after_ticks`: bounded lifetime
  - `attempt_counter_snapshot`: failure counter state at issuance
- Relationships:
  - Created from one `CredentialRecord`
  - May result in one `SessionRecord`
- Validation rules:
  - only one active challenge exists at a time in v1
  - expired or superseded challenges are rejected
  - challenge reuse after success or invalidation is denied

## Entity: SessionRecord

- Fields:
  - `session_id`: active session identifier
  - `role`: authenticated role granted to the session
  - `state`: `inactive`, `pending`, `active`, `expired`, or `invalidated`
  - `issued_at_revision`: device revision when the session became active
  - `expires_at_tick`: bounded expiry marker
  - `last_counter`: last accepted privileged request counter
  - `last_activity_tick`: latest accepted privileged activity marker
  - `bound_authorization_mode`: lifecycle or developer binding context
- Relationships:
  - Established from one `AuthenticationChallenge`
  - Governed by one `RolePolicy`
  - Consulted by every privileged `CommandAuthorization`
- Validation rules:
  - only one `active` authenticated session exists in v1
  - `active` sessions must match current lifecycle and authorization mode
  - expired or invalidated sessions cannot authorize privileged requests
  - session artifacts are cleared on logout, reboot, zeroize, and developer
    reset

## Entity: RequestFreshnessState

- Fields:
  - `session_id`: owning session
  - `next_expected_counter`: monotonic counter floor
  - `highest_accepted_counter`: latest accepted privileged counter
  - `recent_fingerprints`: bounded replay cache for duplicate detection
- Validation rules:
  - counter regression is denied
  - duplicate fingerprint within the replay window is denied
  - freshness state is reset when the session ends

## Entity: AccessFailureCounter

- Fields:
  - `role`: role targeted by the failed attempt
  - `consecutive_failures`: current failure streak
  - `window_failures`: failures inside the active policy window
  - `locked_until_tick`: temporary lockout expiry
  - `last_failure_reason`: summarized denial cause
- Relationships:
  - Associated with one `CredentialRecord`
  - Evaluated against one `RolePolicy`
- Validation rules:
  - lockout is checked before verifier evaluation
  - success resets or decays the configured counters
  - counters survive reboot only if the policy says the lockout must persist

## Entity: SessionStatus

- Fields:
  - `session_present`: whether an authenticated session is active
  - `role`: current active role if present
  - `expires_in_ticks`: bounded remaining lifetime
  - `lockout_active`: whether new authentication attempts are throttled
  - `lockout_role`: role currently under lockout if any
- Validation rules:
  - must never disclose verifier bytes, raw challenge bytes, or reusable proof
    material
  - may be queried only through an explicitly reviewed status command

## Lifecycle and Session Rules

- `inactive -> pending`: `BeginAuthentication` creates a live challenge
- `pending -> active`: `CompleteAuthentication` validates the proof and
  establishes the session
- `pending -> inactive`: challenge expires, is cancelled, or is superseded
- `active -> expired`: timeout or inactivity limit is reached
- `active -> invalidated`: explicit logout, reboot, zeroize, developer reset,
  recovery entry, or incompatible lifecycle change occurs
- any privileged request with missing session, expired session, invalidated
  session, stale counter, duplicate proof, or insufficient role is denied

## Derived Interfaces

- `BeginAuthentication`: request a challenge for a reviewed role
- `CompleteAuthentication`: prove knowledge of the configured verifier and
  establish an authenticated session
- `GetSessionStatus`: obtain non-secret session and lockout status
- `InvalidateSession`: explicitly end the current authenticated session
- privileged existing commands: require an active session with matching role and
  fresh request counter
