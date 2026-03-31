# RP2350 HSM Security Baseline

This repository is for a constrained embedded target, not a certified HSM. That does not justify weak engineering. The baseline below defines the minimum standard for firmware that is allowed to land here.

## Operating rules

- Fail closed. Initialization, clocking, command parsing, authorization, and persistence code must stop safely on invalid state instead of trying to continue.
- Secrets never cross debug interfaces. Keys, seeds, derived material, plaintext PINs, and authorization state must never be logged, echoed, or exposed over USB serial.
- Debug pathways are opt-in. Development transports and verbose logging must be gated behind explicit Cargo features and must not be required for production firmware.
- Keep memory ownership obvious. Avoid aliasing, hidden global state, and long-lived mutable access to secret-bearing buffers.
- Prefer static allocation. Heap growth, fragmentation, and allocator failure modes do not belong in core security paths.
- Minimize unsafe surface area. Any `unsafe` usage must be narrowly scoped, justified in comments, and reviewed as a security-sensitive change.
- Zeroize secrets on every exit path. Temporary key material and plaintext buffers must be cleared as soon as they are no longer needed.
- Authenticate before use. Command handlers must validate framing, length, version, permissions, and authorization state before touching sensitive operations.
- Make state transitions explicit. Security-relevant state machines should be encoded as enums and reviewed for impossible or skipped transitions.
- Keep release builds reproducible and hardened. Shipping images should use aborting panics, LTO, stripped symbols, and overflow checks.

## Code review bar

- No `unwrap`, `expect`, `todo`, `dbg!`, or intentional panics in security-sensitive paths.
- No new transport or storage format without bounds checking, negative tests, and malformed-input handling.
- No feature that mixes debug convenience with production behavior.
- No secret material in unit-test fixtures, example code, or committed logs.

## Next implementation priorities

1. Replace the demo loop with a versioned command dispatcher that rejects unknown or malformed messages by default.
2. Introduce typed secret wrappers with `zeroize` and keep secret-bearing buffers out of logging and formatting traits.
3. Add authenticated command sessions, monotonic anti-replay material, and explicit privilege separation between administration and crypto operations.
4. Define flash layout and key-lifecycle rules before storing any persistent state.
