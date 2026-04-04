# Contract: Hardening Matrix

## Purpose

Define the minimum required hardening coverage for a release candidate.

## Required Verification Classes

### Parser Abuse and Malformed Input

- malformed frame handling
- truncated payload handling
- oversized payload rejection
- invalid command and flag handling

### Authorization and Misuse

- unauthenticated privileged command denial
- wrong-role denial
- replay and freshness denial where applicable
- stale approval or stale transition denial where applicable

### Invalid-State Handling

- command denial from disallowed lifecycle states
- session invalidation after reset/reboot/lockout
- fail-closed behavior after ambiguous or partial transitions

### Persistence Corruption and Recovery

- key-store corruption handling
- audit corruption handling
- rollback-required handling
- restore behavior after interrupted persisted-state updates

### Firmware Update Recovery

- interrupted update handling
- rollback-version denial
- recovery-required behavior after ambiguous activation

### Supply and Build Review

- dependency delta review for changed crates or tooling
- release-build command verification
- artifact identity recording

## Evidence Rules

- Each verification class must cite concrete evidence.
- Evidence may come from software tests, live hardware validation, or documented
  review outputs, but the source must be named explicitly.
- A release cannot compensate for a missing class by passing unrelated checks.
- When the candidate changes persisted state, audit behavior, recovery paths, or
  update activation logic, reviewers should prefer live validation over
  software-only evidence for the affected classes.

## Preferred Repo Evidence Sources

| Category | Typical Evidence Sources |
| --- | --- |
| Parser abuse and malformed input | `protocol` negative tests, contract tests, malformed probe cases |
| Authorization and misuse | protocol tests, CLI denial checks, `cargo probe` role/session coverage |
| Invalid-state handling | protocol state-machine tests, reboot/reset hardware validation |
| Persistence corruption and recovery | firmware persistence tests, developer fault-injection flows |
| Firmware update recovery | signed update probe flow, update-specific quickstart walkthrough |
| Supply and build review | release evidence record, dependency review example, build review example |

## Status Values

- `passed`
- `failed`
- `exception`
- `not-run`

`not-run` and `failed` both block approval unless an approved exception covers
the exact required scope.

## Fail-Closed Reminder

A passing happy-path build, probe run, or operator demo does not compensate for
omitted hardening coverage in another class. Every required class must be
visible and judged directly.
