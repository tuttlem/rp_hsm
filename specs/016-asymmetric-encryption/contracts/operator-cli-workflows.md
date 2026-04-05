# Contract: Operator CLI Workflows

## Purpose

Define the supported `rphsmtool` surface for managed asymmetric encryption and
decryption.

## Required User-Facing Commands

- `rphsmtool list-algorithms`
- `rphsmtool generate-key --algorithm <name> --usage encrypt,decrypt`
- `rphsmtool asym-encrypt --key-id <id> --algorithm <name>`
- `rphsmtool asym-decrypt --key-id <id> --algorithm <name>`
- `rphsmtool get-key-metadata --key-id <id>`
- `rphsmtool list-keys`

## UX Rules

- stdin/stdout remains the default data surface for plaintext and ciphertext
  envelopes
- algorithm choice must be explicit whenever multiple asymmetric-encryption
  profiles are possible
- stdout is result-only; diagnostics remain on stderr
- bounded denials must be readable without looking up raw protocol codes
- documentation must instruct operators to use the `key_id` returned by
  `generate-key`, not fixed example ids

## Regression Sign-Off Surface

The live regression for this feature must cover:

1. reset and provision
2. list supported algorithms
3. generate asymmetric recipient key
4. asymmetric encrypt
5. asymmetric decrypt
6. wrong key or wrong algorithm denial
7. tampered envelope denial
8. post-operation status and key metadata checks
