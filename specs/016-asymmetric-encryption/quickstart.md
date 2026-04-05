# Quickstart: Asymmetric Encryption Operations

## Goal

Prove that a provisioned operator can generate a managed asymmetric recipient
key, encrypt plaintext to it, decrypt the resulting ciphertext back to the
original plaintext, and inspect the supported algorithm profile through the
supported CLI.

## Prerequisites

1. Flash a developer-mode firmware image if live validation requires it.
2. Ensure serial access is configured for the current shell.
3. Have bootstrap and key-manager auth proofs available through environment
   variables.

## Step 1: Reset and Provision

```bash
cargo rphsmtool developer-reset --device /dev/ttyACM0
export RPHSM_BOOT=BOOT
cargo rphsmtool provision --device /dev/ttyACM0 --proof-env RPHSM_BOOT
```

## Step 2: Discover Supported Algorithms

```bash
cargo rphsmtool list-algorithms --device /dev/ttyACM0
```

Confirm the returned set includes the first shipping asymmetric-encryption
profile and does not imply unsupported profiles are usable.

## Step 3: Generate a Managed Recipient Key

```bash
export RPHSM_KEYMG=KEYMG
cargo rphsmtool generate-key --device /dev/ttyACM0 --algorithm x25519-chacha20poly1305 --usage encrypt,decrypt --role key-manager --proof-env RPHSM_KEYMG
```

Use the returned `key_id` in the remaining steps.

## Step 4: Encrypt Plaintext to the Managed Key

```bash
printf 'hello\n' > /tmp/plaintext.txt
cargo rphsmtool asym-encrypt --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --algorithm x25519-chacha20poly1305 --role key-manager --proof-env RPHSM_KEYMG < /tmp/plaintext.txt > /tmp/asym-cipher.bin
```

## Step 5: Decrypt the Ciphertext

```bash
cargo rphsmtool asym-decrypt --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --algorithm x25519-chacha20poly1305 --role key-manager --proof-env RPHSM_KEYMG < /tmp/asym-cipher.bin > /tmp/plaintext.out
cmp /tmp/plaintext.txt /tmp/plaintext.out
```

## Step 6: Inspect Key Metadata

```bash
cargo rphsmtool get-key-metadata --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --role key-manager --proof-env RPHSM_KEYMG
```

Confirm the metadata shows the expected asymmetric-encryption algorithm profile,
usage policy, and public material while not exposing the private component.

## Step 7: Confirm Bounded Denials

Run at least one tampered-envelope or wrong-key attempt and confirm the device
fails closed with a readable denial. Example:

```bash
cp /tmp/asym-cipher.bin /tmp/asym-cipher-tampered.bin
printf '\x00' | dd of=/tmp/asym-cipher-tampered.bin bs=1 seek=12 count=1 conv=notrunc
cargo rphsmtool asym-decrypt --device /dev/ttyACM0 --key-id <RETURNED KEY_ID> --algorithm x25519-chacha20poly1305 --role key-manager --proof-env RPHSM_KEYMG < /tmp/asym-cipher-tampered.bin
```

That should fail because the ciphertext envelope was modified.

## Step 8: Regression Closeout

Before sign-off, rerun the documented `rphsmtool` regression surface for reset,
provision, algorithm discovery, recipient-key generation, asymmetric
encrypt/decrypt, metadata inspection, and denial cases, then run the bounded
engineering regression:

```bash
cargo probe -- --port /dev/ttyACM0
```
