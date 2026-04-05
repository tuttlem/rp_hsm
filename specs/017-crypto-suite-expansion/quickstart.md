# Quickstart: Broadened Crypto Suite

## Goal

Prove that the HSM now supports a broader but still reviewable operator-facing
crypto suite: external sender interoperability for recipient encryption,
managed MAC workflows, managed derivation, and policy-bound wrapped export.

## Prerequisites

1. Flash a developer-mode firmware image if live validation requires it.
2. Ensure serial access is configured for the current shell.
3. Have bootstrap, administrator, and key-manager auth proofs available through
   environment variables.

## Step 1: Reset and Provision

```bash
cargo rphsmtool developer-reset --device /dev/ttyACM0
export RPHSM_BOOT=BOOT
cargo rphsmtool provision --device /dev/ttyACM0 --proof-env RPHSM_BOOT
```

## Step 2: Discover Supported Profiles

```bash
cargo rphsmtool list-algorithms --device /dev/ttyACM0
```

Confirm the output includes the documented broadened profiles and does not imply
unsupported profiles are usable.

## Step 3: External Sender Interoperability

```bash
export RPHSM_KEYMG=KEYMG
cargo rphsmtool generate-key --device /dev/ttyACM0 --algorithm x25519-chacha20poly1305 --usage encrypt,decrypt --role key-manager --proof-env RPHSM_KEYMG
cargo rphsmtool get-key-metadata --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --role key-manager --proof-env RPHSM_KEYMG
```

Use the returned `public_material` with the documented sender-side workflow,
then decrypt the resulting envelope:

```bash
printf 'hello from sender\n' > /tmp/asym-plain.txt
cargo rphsmtool sender-encrypt --algorithm x25519-chacha20poly1305 --public-key-hex <PUBLIC_MATERIAL_HEX> < /tmp/asym-plain.txt > /tmp/sender-envelope.bin
cargo rphsmtool asym-decrypt --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --algorithm x25519-chacha20poly1305 --role key-manager --proof-env RPHSM_KEYMG < /tmp/sender-envelope.bin > /tmp/asym-plain.out
diff -u /tmp/asym-plain.txt /tmp/asym-plain.out
```

The same profile is also available through the managed in-device helper:

```bash
cargo rphsmtool asym-encrypt --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --algorithm x25519-chacha20poly1305 --role key-manager --proof-env RPHSM_KEYMG < /tmp/asym-plain.txt > /tmp/device-envelope.bin
cargo rphsmtool asym-decrypt --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --algorithm x25519-chacha20poly1305 --role key-manager --proof-env RPHSM_KEYMG < /tmp/device-envelope.bin > /tmp/device-plain.out
diff -u /tmp/asym-plain.txt /tmp/device-plain.out
```

## Step 4: Managed MAC Workflow

```bash
cargo rphsmtool generate-key --device /dev/ttyACM0 --algorithm hmac-sha256 --usage mac --role key-manager --proof-env RPHSM_KEYMG
printf 'hello\n' > /tmp/mac-input.txt
cargo rphsmtool mac --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --algorithm hmac-sha256 --role key-manager --proof-env RPHSM_KEYMG < /tmp/mac-input.txt > /tmp/mac.bin
MAC_HEX=$(xxd -p -c 999 /tmp/mac.bin)
cargo rphsmtool verify-mac --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --role key-manager --proof-env RPHSM_KEYMG --mac-hex "$MAC_HEX" < /tmp/mac-input.txt
```

## Step 5: Managed Derivation Workflow

```bash
cargo rphsmtool generate-key --device /dev/ttyACM0 --algorithm p256-ecdh-hkdf-sha256 --usage derive --role key-manager --proof-env RPHSM_KEYMG
cargo rphsmtool get-key-metadata --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --role key-manager --proof-env RPHSM_KEYMG
cargo rphsmtool derive --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --algorithm p256-ecdh-hkdf-sha256 --peer-public-key-hex <PEER_PUBLIC_KEY_HEX> [--context-hex <HEX>] --bytes 32 --role key-manager --proof-env RPHSM_KEYMG > /tmp/derived.bin
```

## Step 6: Wrapped Export Workflow

```bash
cargo rphsmtool generate-key --device /dev/ttyACM0 --algorithm chacha20poly1305 --usage encrypt,decrypt --role key-manager --proof-env RPHSM_KEYMG
cargo rphsmtool generate-key --device /dev/ttyACM0 --algorithm chacha20poly1305 --usage encrypt,decrypt --export-policy wrapped-only --role key-manager --proof-env RPHSM_KEYMG
cargo rphsmtool export-wrapped-key --device /dev/ttyACM0 --key-id <EXPORTABLE KEY_ID> --wrapping-key-id <WRAPPING_KEY_ID> --role key-manager --proof-env RPHSM_KEYMG > /tmp/wrapped-export.bin
cargo rphsmtool import-wrapped-key --device /dev/ttyACM0 --role key-manager --proof-env RPHSM_KEYMG < /tmp/wrapped-export.bin
```

Confirm the export path returns wrapped material only, that non-exportable keys
are denied cleanly, and that the imported copy is restored as non-exportable.

## Step 7: Denial Checks

Run at least one denial from each new family:

- tampered sender envelope
- wrong MAC key usage
- oversized derive output
- non-exportable wrapped export

Each denial should be readable and fail closed.

## Step 8: Regression Closeout

Before sign-off, rerun the documented `rphsmtool` regression surface for
discovery, interoperability, MAC, derive, and wrapped export/import, then run:

```bash
cargo probe -- --port /dev/ttyACM0
```
