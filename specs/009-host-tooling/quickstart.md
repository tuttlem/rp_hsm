# Quickstart: Host Tooling Consolidation and Integration

## Goal

Validate that the supported host tooling surface is coherent for operators and
integrators, and that host-side failure modes are reported clearly without
blurring device policy behavior.

## Prerequisites

1. Build the host tooling:

   ```bash
   cargo build -p host_tools
   ```

2. Ensure a developer-mode device is connected and visible:

   ```bash
   cargo rphsmtool find
   ```

3. Prepare proof material only through environment variables:

   ```bash
   export RPHSM_PROOF=BOOT
   export RPHSM_ADMIN=ADMIN
   export RPHSM_RECOVERY=RECVR
   ```

## Scenario 1: Canonical Operator Flow

Goal: prove routine workflows are possible through `rphsmtool` alone.

1. Reset the lab device if needed:

   ```bash
   cargo rphsmtool developer-reset --device /dev/ttyACM0
   ```

2. Provision the device:

   ```bash
   cargo rphsmtool provision --device /dev/ttyACM0 --proof-env RPHSM_PROOF
   ```

3. Run representative supported workflows:

   ```bash
   cargo rphsmtool status --device /dev/ttyACM0
   cargo rphsmtool get-random --device /dev/ttyACM0 --bytes 16 --role administrator --proof-env RPHSM_ADMIN > /tmp/random.bin
   cargo rphsmtool update-status --device /dev/ttyACM0 --role administrator --proof-env RPHSM_ADMIN
   cargo rphsmtool get-audit-page --device /dev/ttyACM0 --start-sequence 0 --max-events 4 --role administrator --proof-env RPHSM_ADMIN
   ```

Expected outcomes:

- workflows complete without probe-only commands
- stdout remains result-oriented
- denials, if any, are reported accurately

## Scenario 2: Host-Side Access Failure Reporting

Goal: prove common host transport failures are treated as host problems, not as
device policy behavior.

1. Trigger or simulate one representative host-side access failure:
   - busy serial port
   - missing permission
   - competing service holding the port

2. Run a representative command:

   ```bash
   cargo rphsmtool status --device /dev/ttyACM0
   ```

Expected outcomes:

- the tooling reports the failure as host-side access contention or permission
  trouble
- the guidance is actionable
- the error is not mislabeled as a device authorization denial

## Scenario 3: Integration Surface Boundary

Goal: prove the supported integration story is distinct from the human-facing
CLI and the engineering probe.

1. Review the supported surfaces:
   - `rphsmtool` for operators
   - `host_tools::client` for machine integrations
   - `probe_protocol` for engineering validation

2. Confirm a representative workflow does not require parsing human-oriented
   diagnostics to interpret success or failure.

   ```rust
   use host_tools::{ClientConfig, Role, SerialBackend};

   fn example() -> Result<(), Box<dyn std::error::Error>> {
       let backend = SerialBackend::new(ClientConfig::new(
           "/dev/ttyACM0".to_string(),
           115_200,
       ));
       let _status = backend.status_report()?;
       let proof = std::env::var("RPHSM_ADMIN")?;
       let _random = backend.get_random(Role::Administrator, proof.as_bytes(), 16)?;
       Ok(())
   }
   ```

Expected outcomes:

- the canonical operator surface is obvious
- the integration surface is machine-oriented
- the engineering probe is clearly not the default production/operator path
