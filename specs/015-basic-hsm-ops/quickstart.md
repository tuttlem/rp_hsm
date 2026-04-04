# Quickstart: Basic HSM Operations

## Goal

Prove that a provisioned operator can generate managed keys, encrypt and decrypt
data, sign and verify messages, and inspect supported algorithms through the
supported CLI.

## Prerequisites

1. Flash a developer-mode firmware image if live validation requires it.
2. Ensure serial access is configured for the current shell.
3. Have bootstrap and operator auth proofs available through environment
   variables.

## Step 1: Reset and Provision

```bash
cargo rphsmtool developer-reset --device /dev/ttyACM0
export RPHSM_PROOF=BOOT
cargo rphsmtool provision --device /dev/ttyACM0 --proof-env RPHSM_PROOF
```

## Step 2: Discover Supported Algorithms

```bash
cargo rphsmtool list-algorithms --device /dev/ttyACM0
```

Confirm the returned set includes the supported symmetric and signing
algorithms for this feature:

- `chacha20poly1305`
- `aes256gcm`
- `ed25519`
- `p256`

and does not imply unsupported algorithms are usable.

## Step 3: Generate and Use a Symmetric Key

```bash
export RPHSM_KEYMG=KEYMG
printf 'hello\n' > /tmp/plaintext.txt
cargo rphsmtool generate-key --device /dev/ttyACM0 --algorithm chacha20poly1305 --usage encrypt,decrypt --role key-manager --proof-env RPHSM_KEYMG
cargo rphsmtool sym-encrypt --device /dev/ttyACM0 --key-id 1 --algorithm chacha20poly1305 --role key-manager --proof-env RPHSM_KEYMG < /tmp/plaintext.txt > /tmp/cipher.bin
cargo rphsmtool sym-decrypt --device /dev/ttyACM0 --key-id 1 --algorithm chacha20poly1305 --role key-manager --proof-env RPHSM_KEYMG < /tmp/cipher.bin > /tmp/plaintext.out
cmp /tmp/plaintext.txt /tmp/plaintext.out
```

Repeat the same round-trip with `aes256gcm`:

```bash
cargo rphsmtool generate-key --device /dev/ttyACM0 --algorithm aes256gcm --usage encrypt,decrypt --role key-manager --proof-env RPHSM_KEYMG
cargo rphsmtool sym-encrypt --device /dev/ttyACM0 --key-id 2 --algorithm aes256gcm --role key-manager --proof-env RPHSM_KEYMG < /tmp/plaintext.txt > /tmp/cipher.aes.bin
cargo rphsmtool sym-decrypt --device /dev/ttyACM0 --key-id 2 --algorithm aes256gcm --role key-manager --proof-env RPHSM_KEYMG < /tmp/cipher.aes.bin > /tmp/plaintext.aes.out
cmp /tmp/plaintext.txt /tmp/plaintext.aes.out
```

## Step 4: Generate and Use Signing Keys

```bash
printf 'sign me\n' > /tmp/message.bin
cargo rphsmtool generate-key --device /dev/ttyACM0 --algorithm ed25519 --usage sign --role key-manager --proof-env RPHSM_KEYMG
cargo rphsmtool sign --device /dev/ttyACM0 --key-id 3 --role key-manager --proof-env RPHSM_KEYMG < /tmp/message.bin > /tmp/ed25519.sig
```

Retrieve the public material or verification reference from key metadata, then
verify:

```bash
cargo rphsmtool get-key-metadata --device /dev/ttyACM0 --key-id 3 --role key-manager --proof-env RPHSM_KEYMG
SIG_HEX=$(xxd -p -c 999 /tmp/ed25519.sig)
cargo rphsmtool verify --device /dev/ttyACM0 --algorithm ed25519 --public-key-hex <HEX FROM METADATA> --signature-hex "$SIG_HEX" < /tmp/message.bin
```

Then repeat with `p256`:

```bash
cargo rphsmtool generate-key --device /dev/ttyACM0 --algorithm p256 --usage sign --role key-manager --proof-env RPHSM_KEYMG
cargo rphsmtool sign --device /dev/ttyACM0 --key-id 4 --role key-manager --proof-env RPHSM_KEYMG < /tmp/message.bin > /tmp/p256.sig
cargo rphsmtool get-key-metadata --device /dev/ttyACM0 --key-id 4 --role key-manager --proof-env RPHSM_KEYMG
SIG_HEX=$(xxd -p -c 999 /tmp/p256.sig)
cargo rphsmtool verify --device /dev/ttyACM0 --algorithm p256 --public-key-hex <HEX FROM METADATA> --signature-hex "$SIG_HEX" < /tmp/message.bin
```

## Step 5: Confirm Bounded Denials

Run at least one wrong-algorithm or wrong-usage attempt and confirm the device
fails closed with a readable denial. Example:

```bash
cargo rphsmtool sym-encrypt --device /dev/ttyACM0 --key-id 3 --algorithm aes256gcm --role key-manager --proof-env RPHSM_KEYMG < /tmp/plaintext.txt
```

That should fail because key `3` was generated for `ed25519` signing, not
AES-GCM encryption.

## Step 6: Regression Closeout

Before sign-off, rerun the documented `rphsmtool` regression surface for reset,
provision, algorithm discovery, both symmetric round-trips, both signing
workflows, and metadata checks on live hardware.
