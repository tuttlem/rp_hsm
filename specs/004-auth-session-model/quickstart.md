# Quickstart: Authentication and Session Validation

## 1. Validate Unauthenticated Denial

Goal: confirm privileged commands are denied before authentication.

Sequence:

1. Boot the device into a state that allows an administrative role
2. Send a privileged command without any authenticated session
3. Send `GetSessionStatus`

Expected outcomes:

- the privileged command is denied
- no session is created implicitly
- status reports no active authenticated session

## 2. Validate Challenge-Response Session Establishment

Goal: confirm a reviewed role can authenticate and gain only its declared scope.

Sequence:

1. Send `BeginAuthentication` for the desired role
2. Send `CompleteAuthentication` with the returned challenge id and valid proof
3. Send one command allowed for that role
4. Send one command assigned to a different role

Expected outcomes:

- session establishment succeeds only after a valid challenge-response pair
- the allowed command succeeds
- the out-of-scope command is denied with no privilege escalation

## 3. Validate Session Expiry and Explicit Invalidation

Goal: confirm session authority ends exactly when the design says it does.

Sequence:

1. Establish a valid session
2. Let the session expire or trigger the configured inactivity threshold
3. Retry a privileged command
4. Establish a fresh session
5. Send `InvalidateSession`
6. Retry a privileged command

Expected outcomes:

- expired sessions lose authority immediately
- explicit invalidation removes authority immediately
- a new session is required after each termination

## 4. Validate Replay and Freshness Denial

Goal: ensure stale or duplicated privileged authorization material is denied.

Sequence:

1. Establish a valid session
2. Send one privileged command with a fresh request counter
3. Replay the same command with the same counter
4. Send a command with a regressed or stale counter

Expected outcomes:

- the first request succeeds
- replayed and stale-counter requests are denied
- denial does not silently advance session state

## 5. Validate Rate Limiting and Lockout

Goal: confirm repeated failed authentication attempts trigger the documented
protective response.

Sequence:

1. Send `BeginAuthentication` for a reviewed role
2. Send repeated invalid `CompleteAuthentication` proofs until the threshold is
   crossed
3. Retry `BeginAuthentication`
4. Wait for or simulate lockout expiry
5. Authenticate successfully

Expected outcomes:

- failed attempts increment the role-specific failure accounting
- lockout or backoff activates at the documented threshold
- new attempts are denied during lockout
- successful authentication is possible again after the lockout window

## 6. Validate Lifecycle-Driven Session Invalidation

Goal: ensure authority does not survive incompatible device-state changes.

Sequence:

1. Establish a valid administrative or recovery session
2. Trigger a lifecycle transition such as reboot, zeroize, or recovery entry
3. Retry a privileged command using the old session material
4. Query `GetSessionStatus`

Expected outcomes:

- old session material is denied immediately
- status reports the session as absent or invalidated
- a fresh challenge-response flow is required

## 7. Validate Redaction

Goal: prove that auth and session interfaces do not leak reusable secrets.

Sequence:

1. Exercise failed and successful authentication flows
2. Inspect only approved command responses and logs

Expected outcomes:

- verifier data is never returned
- reusable proof material is never returned
- status and denials expose only reviewed non-secret metadata
