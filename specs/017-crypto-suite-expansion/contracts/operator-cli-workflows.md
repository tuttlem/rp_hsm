# Contract: Operator CLI Workflows

## Goal

Define the supported `rphsmtool` workflows for the broadened crypto suite.

## Required CLI Families

- discovery
  - `list-algorithms`
- sender interoperability
  - managed recipient key generation
  - public-material retrieval
  - sender-side envelope generation through `sender-encrypt`
  - managed decrypt
- authentication
  - MAC generation
  - MAC verification
- derivation
  - managed key-agreement key generation
  - derive bounded output
- wrapped key movement
  - wrapped export
  - wrapped import

## CLI Expectations

- Supported workflows MUST be operable through documented commands rather than
  raw protocol construction.
- Generated-key workflows MUST document that operators should use the returned
  `key_id` rather than assuming fixed numeric ids.
- Binary results MUST go to stdout; diagnostics MUST go to stderr.
- Denials and host transport failures MUST remain distinguishable.
- Help text MUST describe these workflows as supported operator surfaces, while
  keeping engineering-only tooling separate.

## Regression Expectations

- Feature signoff MUST include bounded live `rphsmtool` regression for each new
  workflow family.
- Because this feature changes firmware and supported operator behavior, the
  bounded `cargo probe -- --port /dev/ttyACM0` regression is also required.
