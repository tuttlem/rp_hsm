# Contract: Algorithm and Key Policy

## Purpose

Define the operator-visible policy rules for asymmetric-encryption algorithms
and managed recipient keys.

## Supported Profile Rules

- the feature must ship at least one named asymmetric-encryption profile
- the profile name must appear in `rphsmtool list-algorithms`
- unsupported profiles must be denied explicitly and must not appear as
  partially usable entries

## Managed Key Rules

- asymmetric decryption keys are a distinct managed key kind
- asymmetric decryption keys may expose public material through metadata only
- asymmetric decryption keys may be used for encrypt and decrypt only
- asymmetric decryption keys must not be usable for sign, verify, symmetric
  encrypt, or symmetric decrypt

## Lifecycle and State Rules

- key generation is denied outside the allowed lifecycle and session states
- decrypt is denied for revoked, destroyed, or otherwise inactive keys
- encrypt is denied when the selected key record, algorithm, or usage mask does
  not match the request
- state, role, and replay denials must remain distinguishable from host-side
  transport failures

## Documentation Rules

- README and quickstart examples must use the same profile names exposed by the
  CLI
- user-facing docs must show operators how to use the returned `key_id` rather
  than hard-coded example ids that assume a fresh store
