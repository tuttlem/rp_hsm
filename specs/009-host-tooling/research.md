# Research: Host Tooling Consolidation and Integration

## Decision: Treat `009` as consolidation, not first-CLI creation

### Rationale

The repository already has a meaningful host tooling surface:

- `rphsmtool` for operator workflows
- `probe_protocol` for engineering validation
- `host_tools::client` as a reusable host-side command transport layer

The highest remaining value is clarifying support boundaries, closing workflow
gaps, and hardening host-side behavior rather than recreating a CLI capability
that already exists.

### Alternatives considered

- Reframe `009` as a brand-new CLI feature.
  Rejected because that duplicates `014-rphsmtool-cli` and ignores the existing
  codebase reality.

## Decision: The supported integration surface should be the reusable client plus documented output semantics

### Rationale

Integrations should not scrape human-oriented CLI output. The repo already has a
shared client module in `host_tools/src/client.rs`, which is a better basis for
a supported machine-consumable interface. The CLI can still expose structured
output expectations for scripting, but the stable integration story should be:

- canonical operator CLI for humans
- reusable client boundary for software integrations

### Alternatives considered

- Treat raw CLI stdout as the only integration surface.
  Rejected because freeform human-readable output is too fragile as the sole
  machine boundary.
- Treat `probe_protocol` as the integration surface.
  Rejected because it is an engineering validation tool with intentionally broad
  and state-mutating behavior.

## Decision: Busy serial ports and host-side ownership conflicts must be first-class workflow failures

### Rationale

Live validation showed real operator friction from:

- `/dev/ttyACM*` permission ownership
- `ModemManager` grabbing ports after re-enumeration
- long-running probe sessions leaving the device busy

These are not edge curiosities; they are common Linux-host realities for USB
serial devices. The supported host tooling needs explicit detection and
actionable guidance for them.

### Alternatives considered

- Leave raw OS errors unwrapped.
  Rejected because `Device or resource busy` alone does not tell operators how
  to recover safely.
- Assume developer documentation is enough.
  Rejected because host-side access conflicts directly affect the usability of
  the supported operator surface.

## Decision: Packaging should be defined as supported local build/install expectations, not a distribution claim

### Rationale

The workspace already supports `cargo rphsmtool ...` and `cargo run -p
host_tools --bin rphsmtool -- ...`. That is the honest supported install/run
story today. `009` should define:

- how operators build and invoke supported tools from the workspace
- which binary is the canonical operator tool
- which binary is engineering-only

without falsely claiming a packaged installer or OS-native distribution channel
that does not yet exist.

### Alternatives considered

- Pretend a packaged installer exists.
  Rejected because it would overstate product readiness.
- Avoid any install expectations.
  Rejected because users still need a supported way to obtain and run the tool.

## Decision: New firmware capability exposure must be treated as a host-tooling completion requirement

### Rationale

Several recent features were implemented in firmware before the CLI surface was
fully aligned. That produced temporary gaps such as:

- commands implemented but not exposed through `rphsmtool`
- workflows technically possible but only through `probe_protocol`
- partial high-level wrappers that did not complete the intended user flow

`009` should explicitly require a completion rule: when firmware gains a
supported operator-facing capability, host tooling must either expose it
through the canonical surface or document that it remains intentionally
engineering-only.

### Alternatives considered

- Leave host exposure decisions informal.
  Rejected because it repeatedly strands users between product and engineering
  tools.
