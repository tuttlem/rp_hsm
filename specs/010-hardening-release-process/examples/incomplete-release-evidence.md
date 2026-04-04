# Example: Incomplete Release Evidence

## Candidate

- `candidate_id`: `rc-010-demo-incomplete`
- `approval_state`: `draft`
- `artifact_name`: `rp_hsm`
- `artifact_version`: `0.10.0-rc1`
- `artifact_hash`: `sha256:missing`

## Why Approval Fails

- Artifact hash is missing.
- Hardware validation was required for the candidate scope but not run.
- Persistence corruption coverage is still `not-run`.

## Blocking Summary

- `missing_section`: artifact identity completeness
- `missing_section`: live validation
- `missing_check`: `HC-PERSIST-01`

## Result

This candidate cannot move to `review-ready`. The reviewer must reject it or
require the missing evidence to be added first.
