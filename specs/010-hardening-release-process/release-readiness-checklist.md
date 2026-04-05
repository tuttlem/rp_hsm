# Release Readiness Checklist

Use this checklist before marking a candidate approved.

## Candidate Identity

- [ ] Candidate identifier is present
- [ ] Git commit or source reference is recorded
- [ ] Artifact filename, version, and hash are recorded
- [ ] Build target and feature flags are recorded

## Validation Evidence

- [ ] Required workspace validation commands were run
- [ ] Results are recorded for every required command
- [ ] Hardware validation is recorded when the candidate touches hardware-facing behavior
- [ ] Documented `rphsmtool` regression was run when the operator surface changed
- [ ] No secret-bearing material appears in the evidence set

## Hardening Coverage

- [ ] Parser abuse and malformed-input coverage is recorded
- [ ] Authorization and misuse coverage is recorded
- [ ] New crypto-envelope parsing and denial coverage is recorded when the candidate adds or changes encrypt/decrypt surfaces
- [ ] Invalid-state handling coverage is recorded
- [ ] Persistence corruption and recovery coverage is recorded
- [ ] Firmware update recovery coverage is recorded when applicable
- [ ] Supply and build review coverage is recorded

## Dependency and Build Review

- [ ] `Cargo.lock` changes were reviewed or explicitly noted as unchanged
- [ ] Changed manifests or tooling inputs were reviewed
- [ ] Security-relevant dependency impact is summarized
- [ ] Exact build commands and artifact provenance are recorded

## Exceptions and Approval

- [ ] Every exception is tied to one candidate and named checks
- [ ] No non-waivable rule has been waived
- [ ] Open blockers are empty before approval
- [ ] Reviewers and decision timestamp are recorded
- [ ] Approved artifact record references exactly one evidence set
