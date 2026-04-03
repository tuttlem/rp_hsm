# Contract: Session Policy

## Session States

- `inactive`: no active authenticated session
- `pending`: a challenge has been issued but not yet completed
- `active`: an authenticated session is authorized for privileged commands
- `expired`: the session timed out and can no longer authorize requests
- `invalidated`: the session was explicitly or implicitly terminated

## Expiry and Invalidation Conditions

- Expire on:
  - configured session lifetime reached
  - configured inactivity threshold reached
- Invalidate on:
  - explicit `InvalidateSession`
  - reboot
  - zeroize
  - developer reset
  - entry into recovery
  - lifecycle transition that changes role eligibility
  - credential or role-policy change

## Role-Specific Access

- `bootstrap`:
  - may authenticate only in `factory` or `zeroized`
  - authorizes provisioning transitions
- `administrator`:
  - may authenticate in `operational` and `locked`
  - authorizes administrative lifecycle commands reviewed for admin use
- `recovery`:
  - may authenticate in `locked` and `recovery`
  - authorizes recovery transitions only
- `key_manager`:
  - may authenticate in `operational`
  - authorizes persistent key-store management commands
- `developer`:
  - compile-time only in `developer-mode`
  - never available in production builds

## Failure and Lockout Policy

- Each reviewed role maintains bounded failure accounting
- Invalid proof, stale challenge completion, and malformed privileged
  authorization material contribute to failure handling only where doing so does
  not create a host-triggerable denial-of-service against unrelated roles
- After threshold breach:
  - new auth attempts for that role are denied for `lockout_ticks`
  - existing active sessions for that role may be invalidated if the policy
    requires a hard fail-safe response
- Successful authentication resets or decays the role's failure counters

## Fail-Closed Rules

- If credential persistence cannot be trusted, new authenticated sessions are
  denied
- If session state and lifecycle state disagree, privileged access is denied
- If replay tracking state is ambiguous after reboot or corruption, all
  privileged requests are denied until a new session is established
- If a role is not explicitly mapped to a command, the command is denied

## Logging and Status Redaction

- Logs and status responses may include:
  - role identifier
  - denial class
  - lockout active or inactive
  - session present or absent
- Logs and status responses must not include:
  - verifier bytes
  - reusable proofs
  - raw challenge nonces beyond reviewed development instrumentation
  - any secret-bearing session artifact
