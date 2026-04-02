# rp_hsm Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-04-03

## Active Technologies
- Rust edition 2024 with `no_std` firmware and host-side Rust tooling + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing `usb-device`/`usbd-serial` debug transport for development (002-device-state-provisioning)
- Internal flash-backed provisioning record and state journal for durable lifecycle state; bounded in-memory transition workspace and transient authorization buffers (002-device-state-provisioning)
- Rust edition 2024 with `no_std` firmware and host-side Rust tooling + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing `usb-device`/`usbd-serial` developer transport, and existing workspace cargo tooling (003-persistent-key-store)
- Internal flash-backed append-only key journal plus compact key directory/index, monotonic store revision metadata, and bounded in-RAM staging buffers for record assembly and zeroization (003-persistent-key-store)
- Rust edition 2024 with `no_std` firmware and host-side Rust tooling + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing flash persistence backend, and existing `usb-device`/`usbd-serial` developer transport (004-auth-session-model)
- Internal flash-backed lifecycle and authentication snapshot data plus bounded in-RAM session state, replay trackers, and zeroized transient authentication buffers (004-auth-session-model)

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
- 004-auth-session-model: Added Rust edition 2024 with `no_std` firmware and host-side Rust tooling + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing flash persistence backend, and existing `usb-device`/`usbd-serial` developer transport
- 003-persistent-key-store: Added Rust edition 2024 with `no_std` firmware and host-side Rust tooling + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing `usb-device`/`usbd-serial` developer transport, and existing workspace cargo tooling
- 002-device-state-provisioning: Added Rust edition 2024 with `no_std` firmware and host-side Rust tooling + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing `usb-device`/`usbd-serial` debug transport for development


<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
