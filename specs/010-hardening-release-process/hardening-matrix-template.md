# Hardening Matrix Template

## Candidate

- `candidate_id`:
- `candidate_scope`:
- `reviewer`:
- `review_date`:

## Verification Classes

| Check ID | Category | Required Evidence | Candidate Scope | Preferred Evidence Source | Status | Evidence Reference | Live Validation Required | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `HC-PARSER-01` | parser abuse and malformed input | malformed, truncated, oversized, invalid-command rejection | parser, codec, wire protocol changes | protocol tests and negative command cases | `not-run` | | `no` unless parser behavior changed on-device | |
| `HC-MISUSE-01` | authorization and misuse | unauthenticated denial, wrong-role denial, replay or freshness denial | auth, CLI, privileged command changes | protocol tests plus host-tool validation | `not-run` | | `yes` if live auth/session flows changed | |
| `HC-STATE-01` | invalid-state handling | lifecycle denial, session invalidation, ambiguous transition fail-close | lifecycle, recovery, approval, update transitions | protocol tests plus selected hardware flow | `not-run` | | `yes` for persisted or reboot-driven transitions | |
| `HC-PERSIST-01` | persistence corruption and recovery | rollback required, degraded state, restore behavior, audit corruption handling | key store, policy, audit, persistent metadata | firmware tests and developer fault-injection runs | `not-run` | | `yes` if persisted state format or recovery logic changed | |
| `HC-UPDATE-01` | firmware update recovery | interrupted update, equal-version denial, ambiguous activation recovery | update control plane, trusted recovery | probe validation and update-specific walkthrough | `not-run` | | `yes` when update or recovery behavior changed | |
| `HC-SUPPLY-01` | supply and build review | dependency delta review, build commands, artifact identity | workspace dependencies, manifests, build flags | release evidence review | `not-run` | | `no` | |

## Reviewer Rules

- Mark `passed` only when the evidence reference is candidate-specific or still
  clearly valid for the candidate scope.
- Mark `failed` when the class was exercised and did not meet the required
  behavior.
- Mark `exception` only when an approved release exception names this exact
  check and candidate.
- Leave no required class invisible during approval review.
- A successful happy-path build or probe run does not compensate for a missing
  verification class elsewhere in this matrix.
