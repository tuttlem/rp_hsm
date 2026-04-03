# Quickstart: Audit Trail Validation

## 1. Validate Health Status

Goal: prove operators can observe approved device health without a debug-only
backchannel.

Sequence:

1. Boot a developer-mode device and reset it to a clean lab baseline
2. Provision the device and perform at least one privileged action
3. Run `cargo rphsmtool status --device /dev/ttyACM0`
4. Compare the result against current lifecycle, key-store, audit, and policy state

Expected outcomes:

- non-secret state is visible
- no key material, proofs, or approval internals appear
- degraded conditions are reported explicitly when present

Example:

```bash
cargo rphsmtool developer-reset --device /dev/ttyACM0
export RPHSM_PROOF=BOOT
cargo rphsmtool provision --device /dev/ttyACM0 --proof-env RPHSM_PROOF
export RPHSM_PROOF=ADMIN
cargo rphsmtool get-random --device /dev/ttyACM0 --bytes 16 --role administrator --proof-env RPHSM_PROOF > /tmp/random.bin
cargo rphsmtool status --device /dev/ttyACM0
```

## 2. Validate Audit Event Capture

Goal: prove security-relevant actions generate retained audit records.

Sequence:

1. Perform provisioning, at least one allowed privileged action, and at least one denied action
2. Retrieve one or more audit pages as an authorized audit reviewer with `rphsmtool get-audit-page`
3. Inspect event ordering and event classes

Expected outcomes:

- each reviewed action produces a defined audit event
- event ordering is monotonic within retained history
- denial events remain understandable without leaking secrets

Example:

```bash
export RPHSM_PROOF=ADMIN
cargo rphsmtool get-audit-page --device /dev/ttyACM0 --start-sequence 0 --max-events 4 --role administrator --proof-env RPHSM_PROOF
```

## 3. Validate Retention Behavior

Goal: prove bounded storage behaves predictably under pressure.

Sequence:

1. Generate enough auditable actions to fill the audit store
2. Continue generating events past capacity
3. Retrieve the retained window and health status

Expected outcomes:

- overwrite behavior follows the documented oldest-first retention policy
- health status indicates overflow occurred
- retrieval still returns a bounded coherent window

## 4. Validate Authorization And Redaction

Goal: prove observability remains useful without weakening the security
boundary.

Sequence:

1. Attempt audit retrieval without sufficient authority
2. Attempt health retrieval from allowed and disallowed roles if role-specific
   disclosure is implemented
3. Inspect retrieved event and health payloads for sensitive leakage

Expected outcomes:

- unauthorized audit review is denied
- approved health status remains available through the documented path
- no audit or health response exposes key bytes, proof material, or raw secret
  payloads

## 5. Validate Failure And Restart Behavior

Goal: prove audit handling fails closed across persistence faults and restart.

Sequence:

1. Trigger a developer-mode persistence fault or reconstruct from a degraded
   persisted state
2. Request health status and attempt audit retrieval
3. Reboot and recheck observability

Expected outcomes:

- degraded audit state is surfaced via health status
- ambiguous audit retrieval is denied rather than guessed
- restart preserves trustworthy history when persistence is intact
