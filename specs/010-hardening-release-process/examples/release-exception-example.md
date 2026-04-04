# Example: Approved Release Exception

## Exception

- `exception_id`: `rex-010-001`
- `candidate_id`: `rc-010-demo-complete`
- `affected_check_ids`: `HC-UPDATE-01`
- `status`: `approved`

## Issue Summary

Live interrupted-update validation could not be repeated on the approval date
because the dedicated lab board was unavailable.

## Security Impact

Recovery behavior was previously validated on the same candidate scope, but the
fresh live rerun is missing for this approval event.

## Mitigation

- carry forward the prior evidence reference only for this exact candidate
- block any manifest, recovery, or activation changes from using this exception
- rerun the live interrupted-update validation before the next candidate

## Approval

- `approval_owner`: `security-reviewer`
- `expiry_or_revisit_trigger`: next candidate or any update-path code change

## Important

This exception does not waive artifact identity, dependency review, or build
review. It waives one named check for one named candidate only.
