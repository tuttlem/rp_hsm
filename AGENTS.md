# rp_hsm Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-04-02

## Active Technologies
- Rust edition 2024 with `no_std` firmware and host-side Rust tooling + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing `usb-device`/`usbd-serial` debug transport for development (002-device-state-provisioning)
- Internal flash-backed provisioning record and state journal for durable lifecycle state; bounded in-memory transition workspace and transient authorization buffers (002-device-state-provisioning)

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
- 002-device-state-provisioning: Added Rust edition 2024 with `no_std` firmware and host-side Rust tooling + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`, shared `protocol` crate, existing `usb-device`/`usbd-serial` debug transport for development

- 001-secure-command-protocol: Added Rust edition 2024 (`no_std`) + `rp235x-hal`, `embedded-hal`, `heapless`, `critical-section`; existing USB support remains transport scaffolding only

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
