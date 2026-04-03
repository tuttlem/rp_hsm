# rp_hsm Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-04-04

## Active Technologies
- Rust edition 2024 with `no_std` firmware and host-side Rust tooling + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing `usb-device`/`usbd-serial` debug transport for development (002-device-state-provisioning)
- Internal flash-backed provisioning record and state journal for durable lifecycle state; bounded in-memory transition workspace and transient authorization buffers (002-device-state-provisioning)
- Rust edition 2024 with `no_std` firmware and host-side Rust tooling + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing `usb-device`/`usbd-serial` developer transport, and existing workspace cargo tooling (003-persistent-key-store)
- Internal flash-backed append-only key journal plus compact key directory/index, monotonic store revision metadata, and bounded in-RAM staging buffers for record assembly and zeroization (003-persistent-key-store)
- Rust edition 2024 with `no_std` firmware and host-side Rust tooling + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing flash persistence backend, and existing `usb-device`/`usbd-serial` developer transport (004-auth-session-model)
- Internal flash-backed lifecycle and authentication snapshot data plus bounded in-RAM session state, replay trackers, and zeroized transient authentication buffers (004-auth-session-model)
- Rust 2024 edition, `no_std` firmware on RP2350, host tooling on std Rust + existing `heapless`, `rp235x-hal`, `usb-device`, `usbd-serial`, plus reviewed RustCrypto/signature crates for Ed25519 verification/signing, digest handling, and zeroization-compatible secret containers (005-core-crypto-operations)
- existing flash-backed persistent state in `firmware/src/persistence.rs`; no new database or filesystem layer (005-core-crypto-operations)
- Rust stable workspace, aligned with current Cargo workspace + existing `host_tools` crate, shared `protocol` crate, serial-port access crate already used by the probe, CLI argument parsing crate to be selected during implementation (014-rphsmtool-cli)
- N/A for CLI-owned durable storage; transient in-memory handling only (014-rphsmtool-cli)
- Rust 2024 edition with `no_std` firmware and std-based host tooling + existing `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, flash-backed persistence layer, and current host tools / probes; no new third-party policy engine or dynamic rule runtime (006-policy-enforcement)
- internal flash-backed persistent policy profile and bounded approval snapshots plus in-RAM policy-decision context and transient approval evaluation buffers (006-policy-enforcement)
- Rust stable, workspace with `no_std` firmware and host-side Rust CLI + `heapless`, `usb-device`, `usbd-serial`, existing `protocol` shared crate, host-side `serialport` (007-audit-trail)
- Reserved on-device flash via `firmware/src/persistence.rs`; bounded in-memory staging buffers only (007-audit-trail)
- Rust stable workspace, embedded `no_std` firmware on RP2350 and `std` host tooling + existing workspace crates (`protocol`, `host_tools`, `firmware`), RP235x HAL, current serial host tooling, reviewed signature-verification crate for update manifests, existing flash persistence layer (008-signed-firmware-update)
- reserved on-device flash for persisted lifecycle/key/audit state plus new firmware-update metadata and inactive image slot metadata (008-signed-firmware-update)

- Rust edition 2024 (`no_std`) + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`; existing USB support remains transport scaffolding only (001-secure-command-protocol)

## Project Structure

```text
src/
tests/
```

## Commands

cargo test [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] cargo clippy

## Code Style

Rust edition 2024 (`no_std`): Follow standard conventions

## Recent Changes
- 008-signed-firmware-update: Added Rust stable workspace, embedded `no_std` firmware on RP2350 and `std` host tooling + existing workspace crates (`protocol`, `host_tools`, `firmware`), RP235x HAL, current serial host tooling, reviewed signature-verification crate for update manifests, existing flash persistence layer
- 007-audit-trail: Added Rust stable, workspace with `no_std` firmware and host-side Rust CLI + `heapless`, `usb-device`, `usbd-serial`, existing `protocol` shared crate, host-side `serialport`
- 006-policy-enforcement: Added Rust 2024 edition with `no_std` firmware and std-based host tooling + existing `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, flash-backed persistence layer, and current host tools / probes; no new third-party policy engine or dynamic rule runtime


<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
