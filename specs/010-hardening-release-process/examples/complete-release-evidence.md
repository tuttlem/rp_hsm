# Example: Complete Release Evidence

## Candidate

- `candidate_id`: `rc-010-demo-complete`
- `approval_state`: `review-ready`
- `artifact_name`: `rp_hsm`
- `artifact_version`: `0.10.0-rc2`
- `artifact_hash`: `sha256:8d90f8f5example`
- `source_commit`: `abc1234`

## Validation Summary

- Workspace validation commands: all passed
- Live validation: required commands passed on developer-mode hardware
- Hardening matrix: all required checks passed
- Dependency review: no new crates, `Cargo.lock` unchanged
- Build review: artifact provenance recorded

## Result

This candidate can proceed to an approval decision because the evidence set is
complete and no blockers remain.
