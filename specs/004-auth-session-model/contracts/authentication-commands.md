# Contract: Authentication Commands

## Command Set

### `BeginAuthentication`

- Purpose: issue a bounded authentication challenge for a reviewed role
- Request:
  - `role` (`u8`): requested role identifier
- Response payload:
  - `challenge_id` (`u32`)
  - `role` (`u8`)
  - `challenge_nonce_len` (`u8`)
  - `challenge_nonce` (`[u8; N]`)
  - `expires_after_ticks` (`u16`)
- Success conditions:
  - requested role is enabled
  - role is allowed in the current lifecycle state
  - no role lockout is active
- Denial conditions:
  - unknown or disabled role
  - role forbidden in current device state
  - lockout or backoff active
  - malformed request
- Notes:
  - only one active challenge is supported in v1
  - issuing a new challenge invalidates any older in-flight challenge

### `CompleteAuthentication`

- Purpose: validate a role proof and activate a session
- Request:
  - `challenge_id` (`u32`)
  - `request_counter` (`u32`)
  - `proof_len` (`u8`)
  - `proof_bytes` (`[u8; N]`)
- Response payload:
  - `session_id` (`u32`)
  - `role` (`u8`)
  - `session_timeout_ticks` (`u16`)
  - `next_counter` (`u32`)
- Success conditions:
  - challenge exists and is unexpired
  - role verifier matches
  - request counter is valid for session establishment
  - no lockout is active
- Denial conditions:
  - stale or unknown challenge
  - invalid proof
  - stale or duplicated counter
  - role lockout active
  - lifecycle state changed since challenge issuance
- Notes:
  - any failure updates failure accounting
  - successful completion invalidates the challenge immediately

### `GetSessionStatus`

- Purpose: return non-secret session and lockout state
- Request:
  - empty payload
- Response payload:
  - `session_present` (`u8`)
  - `active_role` (`u8`)
  - `expires_in_ticks` (`u16`)
  - `lockout_active` (`u8`)
  - `lockout_role` (`u8`)
- Notes:
  - response must not include reusable proofs, verifier bytes, or raw challenge
    material

### `InvalidateSession`

- Purpose: explicitly terminate the current authenticated session
- Request:
  - `session_id` (`u32`)
  - `request_counter` (`u32`)
- Response payload:
  - `result_state` (`u8`): `inactive`
- Success conditions:
  - session exists
  - session id matches current active session
  - request counter is fresh
- Denial conditions:
  - no active session
  - stale or mismatched session id
  - stale or duplicated request counter

## Authorization Rules

- `BeginAuthentication`: public access, but only for reviewed roles exposed in
  the current lifecycle state
- `CompleteAuthentication`: public access to the pending challenge, but denial
  is fail-closed on any ambiguity
- `GetSessionStatus`: public or minimally scoped status access, provided the
  response remains non-secret
- `InvalidateSession`: requires the currently active authenticated session or
  developer-mode override in non-production builds

## Freshness Rules

- `CompleteAuthentication` must consume a live challenge exactly once
- Every privileged command after session establishment carries a `session_id`
  and `request_counter`
- Request counters must increase monotonically within the session
- Duplicate or stale counters are denied with no state change

## Defensive Behavior

- Failed proofs increment role-specific failure counters
- Once the threshold is crossed, `BeginAuthentication` and
  `CompleteAuthentication` deny further attempts until lockout expires
- Reboot, zeroize, developer reset, recovery entry, and credential-policy
  changes invalidate the current session immediately
