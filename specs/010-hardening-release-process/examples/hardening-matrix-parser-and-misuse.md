# Example: Hardening Matrix for Parser and Misuse Coverage

## Candidate

- `candidate_id`: `rc-010-parser-misuse`
- `candidate_scope`: parser, session, and CLI denial-path wording

| Check ID | Category | Status | Evidence Reference | Notes |
| --- | --- | --- | --- | --- |
| `HC-PARSER-01` | parser abuse and malformed input | `passed` | protocol negative tests for malformed frames and invalid commands | Covers truncation, oversize, and unknown-command rejection |
| `HC-MISUSE-01` | authorization and misuse | `passed` | `cargo probe -- --port /dev/ttyACM0` plus targeted CLI denial checks | Covers wrong-role, unauthenticated, replay-sensitive denial paths |
| `HC-STATE-01` | invalid-state handling | `passed` | protocol tests for disallowed lifecycle/session states | Confirms fail-closed denials from disallowed states |

## Review Note

These checks are all visible independently. A green happy-path auth flow would
not have been enough without the negative evidence above.
