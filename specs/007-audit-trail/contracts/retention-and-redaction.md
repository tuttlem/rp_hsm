# Contract: Retention And Redaction

## Retention

- Audit storage is fixed-capacity and bounded at compile time.
- When capacity is reached, the oldest retained events are overwritten.
- The device increments an overflow counter or equivalent retained summary when
  overwrite occurs.
- Retrieval returns only currently retained events; the interface does not claim
  complete device lifetime history.

## Failure Handling

- If audit persistence fails during a command, the device must fail closed with a
  bounded status rather than silently claiming success.
- If audit storage cannot be decoded or reconstructed safely on boot, the device
  must mark the audit store degraded and deny trusted replay of ambiguous data.
- Health status must expose the degraded/overflow condition without exposing raw
  internal storage bytes.

## Redaction

Allowed audit detail examples:

- event/result class
- actor role
- command family or command identifier
- lifecycle transition type
- key identifier when already non-secret metadata
- bounded denial class

Forbidden audit detail examples:

- auth proofs
- raw request payloads that can carry secret material
- key bytes or wrapped key ciphertext
- session secrets, approval markers, or transport noise

## Role Disclosure Levels

- Public/low-privilege health callers receive only approved health summary.
- Audit-review roles receive bounded event records.
- Developer-only commands may expose additional lab-only observability in
  developer builds, but never secret material.

## Current CLI Surface

- `rphsmtool status` exposes the redacted health summary.
- `rphsmtool get-audit-page` exposes bounded authorized audit retrieval.
- Audit output is metadata-only and hex-encodes bounded detail bytes.
