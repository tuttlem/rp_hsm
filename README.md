# RP2350 HSM Workspace

This repository is a Cargo workspace with three crates:

- `firmware`: the embedded RP2350 firmware image
- `protocol`: shared protocol and wire-format library
- `host_tools`: desktop utilities for probing and testing the device

Keep this file aligned with:

- [.cargo/config.toml](/home/michael/src/embedded/rp_hsm/.cargo/config.toml)
- new workspace binaries under [host_tools/src/bin](/home/michael/src/embedded/rp_hsm/host_tools/src/bin)
- any new firmware features that change the required invocation flags

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

Policy-enforcement note:

- `006-policy-enforcement` adds bounded denial classes to command responses.
  Current host tooling renders these as role/session denial, key-policy denial,
  state denial, approval-required, approval-stale, or internal-policy
  ambiguity.
- The persisted policy profile defaults to the single-reviewed-path behavior so
  existing operator flows remain usable.
- Dual-control approval-ticket behavior is implemented and covered by protocol
  tests, but there is not yet a runtime host command to toggle that policy on a
  live device. Hardware probe coverage therefore validates the bounded denial
  surface and reviewed default path, while dual-control approval semantics are
  regression-tested in the protocol crate.

Important:

- The firmware still reserves the top 8 KiB of the configured 2 MiB flash image
  for developer-mode persistent-state snapshots. That space is outside the
  linked application image.
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
cargo rphsmtool sign --device /dev/ttyACM0 --key-id 1 --role key-manager --proof-env RPHSM_PROOF < message.bin > signature.bin
cargo rphsmtool verify --device /dev/ttyACM0 --algorithm ed25519 --public-key-hex <HEX> --signature-hex <HEX> < message.bin
cargo rphsmtool import-wrapped-key --device /dev/ttyACM0 --role key-manager --proof-env RPHSM_PROOF < envelope.bin
cargo rphsmtool list-keys --device /dev/ttyACM0 --role key-manager --proof-env RPHSM_PROOF
cargo rphsmtool get-key-metadata --device /dev/ttyACM0 --key-id 1 --role key-manager --proof-env RPHSM_PROOF
cargo rphsmtool revoke-key --device /dev/ttyACM0 --key-id 1 --role key-manager --proof-env RPHSM_PROOF
cargo rphsmtool destroy-key --device /dev/ttyACM0 --key-id 1 --role key-manager --proof-env RPHSM_PROOF
```

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
- `sign` writes raw signature bytes to stdout.
- `verify` reads the message from stdin and writes `true` or `false` to stdout.
- Authentication proof input is taken from `--proof-env <VAR>` to avoid putting
  proof material into shell history.
- Reserved future verbs such as `sym-encrypt` and `sym-decrypt` fail explicitly
  instead of pretending to work before the firmware supports them.

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
cargo rphsmtool find
```

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
