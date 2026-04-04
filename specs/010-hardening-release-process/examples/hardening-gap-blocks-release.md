# Example: Missing Hardening Class Blocks Release

## Candidate

- `candidate_id`: `rc-010-gap-blocked`
- `candidate_scope`: firmware update recovery changes

## Matrix Snapshot

| Check ID | Category | Status | Evidence Reference | Notes |
| --- | --- | --- | --- | --- |
| `HC-PARSER-01` | parser abuse and malformed input | `passed` | protocol negative tests | |
| `HC-MISUSE-01` | authorization and misuse | `passed` | CLI denial checks | |
| `HC-STATE-01` | invalid-state handling | `passed` | reboot/state validation | |
| `HC-PERSIST-01` | persistence corruption and recovery | `passed` | corruption-injection walkthrough | |
| `HC-UPDATE-01` | firmware update recovery | `not-run` | | Missing ambiguous-activation recovery evidence |
| `HC-SUPPLY-01` | supply and build review | `passed` | release evidence review | |

## Result

Release is blocked. Passing five classes does not compensate for the omitted
firmware update recovery class.
