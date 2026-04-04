# Example: Build Review

## Candidate

- `candidate_id`: `rc-010-build-review`
- `artifact_name`: `rp_hsm`
- `artifact_version`: `0.10.0-rc3`

## Build Commands

```bash
cargo test -p rp_hsm --target x86_64-unknown-linux-gnu
cargo test -p host_tools
cargo clippy -p rp_hsm --target x86_64-unknown-linux-gnu --tests -- -W clippy::pedantic
cargo clippy -p host_tools -- -W clippy::pedantic
cargo build -p firmware --target riscv32imac-unknown-none-elf --features developer-mode
```

## Artifact Identity

- `artifact_path`: `target/riscv32imac-unknown-none-elf/debug/rp_hsm`
- `artifact_hash`: `sha256:4dc0example`
- `source_commit`: `def5678`
- `feature_flags`: `developer-mode`

## Provenance Note

The approved artifact record must be sufficient for a later reviewer to match
the approved binary back to the reviewed source revision and build invocation.
