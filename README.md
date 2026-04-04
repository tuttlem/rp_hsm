# RP2350 HSM Workspace

This repository is a Cargo workspace with three crates:

- `firmware`: the embedded RP2350 firmware image
- `protocol`: shared protocol and wire-format library
- `host_tools`: desktop utilities for probing and testing the device

Keep this file aligned with:

- [.cargo/config.toml](/home/michael/src/embedded/rp_hsm/.cargo/config.toml)
- new workspace binaries under [host_tools/src/bin](/home/michael/src/embedded/rp_hsm/host_tools/src/bin)
- any new firmware features that change the required invocation flags

## Supported Host Surfaces

- `cargo rphsmtool`: supported operator CLI
- `host_tools::client`: supported machine-consumable host integration surface
- `cargo probe`: engineering validation tool

Do not treat `probe_protocol` output as a stable integration API. It is meant
to exercise the device aggressively during development, not to be the default
operator or application boundary.

## Release Readiness

Release approval is evidence-based and fail-closed. A candidate is not ready
because it "seems done"; it is ready only when a repo-tracked release record
identifies the exact artifact, the exact source revision, the required
validation evidence, the hardening coverage, and any explicit exceptions.

The release-process artifacts live under
[`specs/010-hardening-release-process`](/home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process).
Use these files when preparing a candidate:

- [release-evidence-template.md](/home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-evidence-template.md)
- [hardening-matrix-template.md](/home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/hardening-matrix-template.md)
- [release-exception-template.md](/home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-exception-template.md)
- [approved-artifact-template.md](/home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/approved-artifact-template.md)
- [release-readiness-checklist.md](/home/michael/src/embedded/rp_hsm/specs/010-hardening-release-process/release-readiness-checklist.md)

Minimum release expectations:

- artifact identity must be complete
- required workspace validation must be recorded
- required hardware validation must be recorded when the candidate touches
  hardware-facing security behavior
- every hardening class must be visible and judged directly
- dependency review and build review must be recorded
- missing evidence blocks approval unless an explicit scoped exception exists

## Common Commands

### Build firmware

Build the firmware crate for the RP2350 RISC-V target:

```bash
cargo build -p firmware --target riscv32imac-unknown-none-elf
```

Build firmware with `developer-mode` enabled:

```bash
cargo build -p firmware --target riscv32imac-unknown-none-elf --features developer-mode
```

Alias form:

```bash
cargo firmware-build
cargo firmware-build --features developer-mode
```

`cargo build` and `cargo firmware-build` only compile artifacts. They do not flash the device.

### Flash firmware

Build and flash firmware using the configured `picotool` runner:

```bash
cargo run -p firmware --target riscv32imac-unknown-none-elf
```

Build and flash firmware with `developer-mode` enabled:

```bash
cargo run -p firmware --target riscv32imac-unknown-none-elf --features developer-mode
```

Alias form:

```bash
cargo firmware-run
cargo firmware-run-developer
```

Important:

- `cargo firmware-run` flashes the default firmware image without `developer-mode`.
- `cargo firmware-run-developer` flashes the firmware image with `--features developer-mode`.
- The USB CDC device and developer-only lifecycle reset path are only present when the flashed image includes `--features developer-mode`.
- Building a `developer-mode` image and then flashing the default image will remove `/dev/ttyACM*` again.

Recommended developer workflow:

```bash
cargo firmware-run-developer
ls /dev/ttyACM*
```

`developer-mode` is a non-production feature bundle. It enables the USB CDC transport, developer probe access, and the developer-only lifecycle reset command used to recover lab devices from bad state.

### Run the host probe

Run the Rust protocol probe against the default serial device:

```bash
cargo run -p host_tools --bin probe_protocol -- --port /dev/ttyACM0
```

Use a specific baud rate:

```bash
cargo run -p host_tools --bin probe_protocol -- --port /dev/ttyACM0 --baud 115200
```

Alias form:

```bash
cargo probe -- --port /dev/ttyACM0
cargo probe -- --port /dev/ttyACM0 --baud 115200
```

Show probe help:

```bash
cargo probe -- --help
```

The probe expects a `developer-mode` firmware image and validates:

1. protocol version and public command catalog shape
2. developer-mode restricted catalog visibility for `DeveloperResetLifecycle`, `DeveloperStoreFault`, `DeveloperReboot`, and `DeveloperSetPolicy`
3. unauthenticated denial of privileged commands
4. bootstrap authentication and provisioning from `factory` to `operational`
5. public crypto capability discovery
6. administrator authentication, lock, unlock, bounded random generation, and immediate session invalidation
7. key-manager authentication, managed signing, detached verification, wrapped import, persistent key operations, replay denial, and explicit logout
8. session expiry after bounded inactivity
9. repeated failed authentication attempts triggering lockout
10. reboot-driven invalidation of active authenticated sessions
11. developer-only lifecycle reset back to `factory`
12. signed firmware update control-plane behavior, including signed manifest
    acceptance, version rollback denial, and recovery-required boot after an
    injected ambiguous activation fault

Policy-enforcement note:

- `006-policy-enforcement` adds bounded denial classes to command responses.
  Current host tooling renders these as role/session denial, key-policy denial,
  state denial, approval-required, approval-stale, or internal-policy
  ambiguity.
- The persisted policy profile defaults to the single-reviewed-path behavior so
  existing operator flows remain usable.
- `developer-set-policy` can now toggle `dual_control_enabled` on a live
  developer-mode device for lab validation of approval-ticket flows.

Important:

- The firmware still reserves the top 8 KiB of the configured 2 MiB flash image
  for developer-mode persistent-state snapshots. That space is outside the
  linked application image.
- `008-signed-firmware-update` currently implements a signed update control
  plane, version floor, staged slot metadata, and trusted recovery semantics.
  It does not claim a production bootloader handoff or self-reflash path beyond
  that modeled update state.
- `cargo probe` is an on-device validation command. It will mutate lifecycle
  state, authenticate multiple reviewed roles, reboot the board once, and issue
  a developer reset when cleanup is required.
- The reserved persistent-state flash region is intentionally preserved across
  normal firmware reflashes. In `developer-mode`, the probe will issue a
  developer reset automatically if the device boots with previously persisted
  lab state.

If the probe fails with `Permission denied`, check the device node ownership first:

```bash
ls -l /dev/ttyACM0
```

Do not assume the serial access group is always `dialout`. On some systems it may be `uucp` or another group. Add your user to whatever group owns the device node, then log out and back in before retrying:

```bash
id
groups
```

Example:

```bash
sudo usermod -aG uucp $USER
```

If your system shows a different group on `/dev/ttyACM0`, use that group instead.

### Run `rphsmtool`

`rphsmtool` is the user-facing CLI. It keeps stdout result-only, stderr
diagnostic-only, and hides protocol framing, counters, and session setup from
operators.

Run it directly:

```bash
cargo run -p host_tools --bin rphsmtool -- find
```

Alias form:

```bash
cargo rphsmtool find
```

Typical commands:

```bash
cargo rphsmtool find
cargo rphsmtool status --device /dev/ttyACM0
cargo rphsmtool developer-reset --device /dev/ttyACM0
cargo rphsmtool developer-reboot --device /dev/ttyACM0
cargo rphsmtool developer-store-fault --device /dev/ttyACM0 --action rollback-persisted-store
cargo rphsmtool developer-store-fault --device /dev/ttyACM0 --action corrupt-persisted-audit
cargo rphsmtool developer-set-policy --device /dev/ttyACM0 --dual-control on
cargo rphsmtool provision-bootstrap --device /dev/ttyACM0 --proof-env RPHSM_PROOF
cargo rphsmtool auth-check --device /dev/ttyACM0 --role administrator --proof-env RPHSM_PROOF
cargo rphsmtool lock --device /dev/ttyACM0 --role administrator --proof-env RPHSM_PROOF
cargo rphsmtool unlock --device /dev/ttyACM0 --role administrator --proof-env RPHSM_PROOF
cargo rphsmtool zeroize --device /dev/ttyACM0 --role administrator --proof-env RPHSM_PROOF
cargo rphsmtool logout --device /dev/ttyACM0 --role administrator --proof-env RPHSM_PROOF
cargo rphsmtool enter-recovery --device /dev/ttyACM0 --role recovery --proof-env RPHSM_PROOF
cargo rphsmtool recover-to-provisioned --device /dev/ttyACM0 --role recovery --proof-env RPHSM_PROOF
cargo rphsmtool reactivate-recovered --device /dev/ttyACM0 --transition-id 7 --role recovery --proof-env RPHSM_PROOF
cargo rphsmtool get-random --device /dev/ttyACM0 --bytes 32 --role administrator --proof-env RPHSM_PROOF
cargo rphsmtool get-audit-page --device /dev/ttyACM0 --start-sequence 0 --max-events 4 --role administrator --proof-env RPHSM_PROOF
cargo rphsmtool update-status --device /dev/ttyACM0 --role administrator --proof-env RPHSM_PROOF
cargo rphsmtool apply-update --device /dev/ttyACM0 --image update.bin --version 1.0.0.1 --role administrator --proof-env RPHSM_PROOF
cargo rphsmtool abort-update --device /dev/ttyACM0 --session-id 7 --role administrator --proof-env RPHSM_PROOF
cargo rphsmtool recover-trusted-firmware --device /dev/ttyACM0 --role recovery --proof-env RPHSM_PROOF
cargo rphsmtool developer-update-fault --device /dev/ttyACM0 --action ambiguous-firmware-activation
cargo rphsmtool sign --device /dev/ttyACM0 --key-id 1 --role key-manager --proof-env RPHSM_PROOF < message.bin > signature.bin
cargo rphsmtool verify --device /dev/ttyACM0 --algorithm ed25519 --public-key-hex <HEX> --signature-hex <HEX> < message.bin
cargo rphsmtool import-wrapped-key --device /dev/ttyACM0 --role key-manager --proof-env RPHSM_PROOF < envelope.bin
cargo rphsmtool list-keys --device /dev/ttyACM0 --role key-manager --proof-env RPHSM_PROOF
cargo rphsmtool get-key-metadata --device /dev/ttyACM0 --key-id 1 --role key-manager --proof-env RPHSM_PROOF
cargo rphsmtool revoke-key --device /dev/ttyACM0 --key-id 1 --role key-manager --proof-env RPHSM_PROOF
cargo rphsmtool destroy-key --device /dev/ttyACM0 --key-id 1 --role key-manager --proof-env RPHSM_PROOF
```

Future feature work should update the release evidence set when it changes:

- required validation commands
- required hardware walkthroughs
- hardening classes or evidence sources
- operator or reviewer guidance

Behavior:

- `find` enumerates compatible RP HSM devices only.
- `developer-reset` returns a developer-mode lab device to `factory` so fresh
  bootstrap workflows can be rerun.
- `developer-reboot` and `developer-store-fault` are exposed for lab validation
  and only succeed when the connected firmware includes the developer-only
  command set.
- `developer-set-policy` toggles developer-only policy switches such as
  `dual_control_enabled` and persists the updated policy profile for later
  validation.
- `provision-bootstrap` performs the reviewed bootstrap auth plus begin/finalize
  provisioning flow needed to move a factory-state device into a usable state.
- `auth-check` verifies that a reviewed role can authenticate successfully
  without requiring users to construct protocol frames manually.
- `lock`, `unlock`, `zeroize`, `logout`, recovery transitions, `sign`,
  `verify`, `import-wrapped-key`, `revoke-key`, and `destroy-key` all map to
  already-implemented firmware operations.
- If `--device` is omitted, `rphsmtool` auto-selects only when exactly one
  compatible device is present.
- If multiple compatible devices are present, the command fails closed and
  requires `--device`.
- `get-random` writes raw bytes to stdout and sends any diagnostics to stderr.
- `get-audit-page` writes bounded audit entry metadata to stdout and keeps
  secret-bearing request material out of the rendered output.
- `update-status`, `apply-update`, `abort-update`, and
  `recover-trusted-firmware` expose the signed-update workflow already present
  in firmware. `apply-update` stages, finalizes, and activates a bounded signed
  image package through the existing update control plane.
- `developer-update-fault` injects developer-only firmware-update ambiguity or
  rollback conditions for live recovery validation.
- `sign` writes raw signature bytes to stdout.
- `verify` reads the message from stdin and writes `true` or `false` to stdout.
- Authentication proof input is taken from `--proof-env <VAR>` to avoid putting
  proof material into shell history.
- Reserved future verbs such as `sym-encrypt` and `sym-decrypt` fail explicitly
  instead of pretending to work before the firmware supports them.
- Busy serial ports, missing permissions, and missing/re-enumerated device
  nodes are reported as host-side transport issues with actionable hints instead
  of being mislabeled as device authorization failures.

For machine integrations, prefer the supported Rust client surface instead of
scraping CLI output. A minimal example looks like this:

```rust
use host_tools::{ClientConfig, Role, SerialBackend};

fn read_status() -> Result<(), Box<dyn std::error::Error>> {
    let backend = SerialBackend::new(ClientConfig::new(
        "/dev/ttyACM0".to_string(),
        115_200,
    ));
    let report = backend.status_report()?;
    println!("device_state={}", report.device_state);

    let proof = std::env::var("RPHSM_PROOF")?;
    let random = backend.get_random(Role::Administrator, proof.as_bytes(), 16)?;
    println!("random_len={}", random.len());
    Ok(())
}
```

Examples:

```bash
cargo rphsmtool developer-reset --device /dev/ttyACM0
```

```bash
export RPHSM_PROOF=BOOT
cargo rphsmtool provision-bootstrap --device /dev/ttyACM0 --proof-env RPHSM_PROOF
```

```bash
export RPHSM_PROOF=ADMIN
cargo rphsmtool get-random --device /dev/ttyACM0 --bytes 16 --role administrator --proof-env RPHSM_PROOF > random.bin
```

```bash
cargo rphsmtool get-audit-page --device /dev/ttyACM0 --start-sequence 0 --max-events 4 --role administrator --proof-env RPHSM_PROOF
```

```bash
export RPHSM_PROOF=ADMIN
cargo rphsmtool apply-update --device /dev/ttyACM0 --image update.bin --version 1.0.0.1 --role administrator --proof-env RPHSM_PROOF
```

```bash
cargo rphsmtool find
```

### Audit and Health Validation

`007-audit-trail` adds two operator-facing observability surfaces:

- `status`, which now includes a redacted health summary
- `get-audit-page`, which returns a bounded authorized audit page

Typical validation flow:

```bash
cargo rphsmtool developer-reset --device /dev/ttyACM0
export RPHSM_PROOF=BOOT
cargo rphsmtool provision --device /dev/ttyACM0 --proof-env RPHSM_PROOF
export RPHSM_PROOF=ADMIN
cargo rphsmtool get-random --device /dev/ttyACM0 --bytes 16 --role administrator --proof-env RPHSM_PROOF > /tmp/random.bin
cargo rphsmtool status --device /dev/ttyACM0
cargo rphsmtool get-audit-page --device /dev/ttyACM0 --start-sequence 0 --max-events 4 --role administrator --proof-env RPHSM_PROOF
```

The audit page output is metadata-only. It does not expose key material,
authentication proofs, wrapped-key envelopes, or other raw secret payloads.

If serial permissions require a group such as `uucp`, run the command from a
shell with that group applied or after logging back in with updated group
membership.

### Test the protocol crate

Run protocol tests on the host target:

```bash
cargo test -p rp_hsm --target x86_64-unknown-linux-gnu
```

Run protocol linting on the host target:

```bash
cargo clippy -p rp_hsm --target x86_64-unknown-linux-gnu --tests -- -W clippy::pedantic
```

### Build individual crates

Build the shared protocol crate:

```bash
cargo build -p rp_hsm
```

Build the host tools crate:

```bash
cargo build -p host_tools
```

### Inspect available probe arguments

```bash
cargo run -p host_tools --bin probe_protocol -- --help
```

## Current Cargo Aliases

Defined in [.cargo/config.toml](/home/michael/src/embedded/rp_hsm/.cargo/config.toml):

- `cargo firmware-build`
- `cargo firmware-run`
- `cargo firmware-run-developer`
- `cargo probe -- ...`
- `cargo rphsmtool ...`

## Maintenance Rule

When adding or changing:

- Cargo aliases
- host-side binaries
- firmware run modes
- required feature flags

update this README in the same change.
