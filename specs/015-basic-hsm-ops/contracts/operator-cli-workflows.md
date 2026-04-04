# Contract: Operator CLI Workflows

## Purpose

Define the supported `rphsmtool` surface for the new basic HSM operations.

## Required User-Facing Commands

- `rphsmtool list-algorithms`
- `rphsmtool generate-key --algorithm <name> --usage <set>`
- `rphsmtool sym-encrypt --key-id <id> --algorithm <name>`
- `rphsmtool sym-decrypt --key-id <id> --algorithm <name>`
- `rphsmtool sign --key-id <id>`
- `rphsmtool verify --algorithm <name> ...`
- `rphsmtool get-key-metadata --key-id <id>`
- `rphsmtool list-keys`

## UX Rules

- stdin/stdout remains the default data surface for plaintext, ciphertext, and
  detached signatures
- algorithm choice must be explicit whenever multiple supported algorithms are
  possible
- stdout is result-only; diagnostics remain on stderr
- unsupported algorithms and policy denials must be readable without looking up
  raw protocol codes

## Regression Sign-Off Surface

The live regression for this feature must cover:

1. reset and provision
2. list supported algorithms
3. generate symmetric key
4. symmetric encrypt/decrypt round trip
5. generate signing key
6. sign/verify round trip
7. wrong algorithm or wrong usage denial
8. post-operation status and key metadata checks
