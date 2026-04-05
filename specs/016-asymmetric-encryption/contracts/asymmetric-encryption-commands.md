# Contract: Asymmetric Encryption Commands

## Purpose

Define the externally reachable command surface needed for managed asymmetric
encryption and decryption.

## Required Capabilities

- list supported asymmetric-encryption profiles
- generate a managed asymmetric decryption key
- encrypt plaintext to a managed recipient key
- decrypt a bounded asymmetric ciphertext envelope with a managed private key
- inspect recipient public material through key metadata

## Required Command Behaviors

- every asymmetric-encryption request must carry an explicit algorithm profile
- key generation must return enough metadata for the operator to identify the
  new key record without exposing the private component
- encrypt must return a bounded ciphertext envelope containing all non-secret
  fields needed for later decryption
- decrypt must accept only a well-formed envelope for the selected profile and
  return plaintext only on success
- malformed, wrong-key, wrong-usage, wrong-state, and unsupported-profile cases
  must fail closed with bounded denials

## Required Authorization Rules

- recipient-key generation requires authenticated `key-manager` authority
- encrypt and decrypt require authenticated `key-manager` authority unless a
  later policy change explicitly broadens the caller surface
- operations must respect replay controls, lifecycle state, key state, and
  policy gates already established by prior features

## Required Regression Surface

The live hardware regression for this feature must cover:

1. algorithm discovery
2. recipient-key generation
3. asymmetric encrypt
4. asymmetric decrypt
5. malformed or tampered envelope denial
6. wrong key or wrong algorithm denial
7. post-operation metadata and status checks
