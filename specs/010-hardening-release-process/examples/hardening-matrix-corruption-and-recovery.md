# Example: Hardening Matrix for Corruption and Recovery Coverage

## Candidate

- `candidate_id`: `rc-010-corruption-recovery`
- `candidate_scope`: persistent state, audit restore, firmware update recovery

| Check ID | Category | Status | Evidence Reference | Notes |
| --- | --- | --- | --- | --- |
| `HC-PERSIST-01` | persistence corruption and recovery | `passed` | developer fault-injection flows for rollback-required, degraded key store, and locked audit state | Confirms fail-closed restore behavior |
| `HC-UPDATE-01` | firmware update recovery | `passed` | signed update probe sequence covering equal-version denial and ambiguous activation recovery | Confirms trusted recovery path remains explicit |
| `HC-STATE-01` | invalid-state handling | `passed` | reboot and session invalidation validation | Confirms no partial transition survives ambiguous restore |

## Review Note

Candidate touched persistent metadata, so software tests alone were not
accepted. Live hardware evidence was required and recorded.
