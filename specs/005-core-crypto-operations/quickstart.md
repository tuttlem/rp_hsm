# Quickstart: Core Crypto Operations Validation

## 1. Validate Public Capability Discovery

Goal: confirm the device exposes only the reviewed crypto surface.

Sequence:

1. Send `GetCryptoCapabilities`
2. Record the supported operation flags and size bounds

Expected outcomes:

- capability output includes signing, verification, random generation, and
  wrapped import only if enabled for this feature
- excluded classes such as decrypt, encrypt, export, and key agreement are not
  advertised

## 2. Validate Managed Signing

Goal: confirm managed keys can perform only approved signing operations.

Sequence:

1. Authenticate as key manager
2. Send `SignDetached` for an active Ed25519 key with an allowed message length
3. Retry `SignDetached` with a key that is revoked, destroyed, or lacks signing
   usage

Expected outcomes:

- the approved signing request succeeds and returns a detached signature
- incompatible keys are denied with no secret exposure

## 3. Validate Public Verification

Goal: confirm detached verification works without widening secret exposure.

Sequence:

1. Send `VerifyDetached` with a valid message, public key, and signature
2. Send `VerifyDetached` with an altered signature
3. Send `VerifyDetached` with malformed or oversized fields

Expected outcomes:

- valid requests return `verified = true`
- altered signatures return `verified = false`
- malformed requests fail closed with validation or command denial

## 4. Validate Random Generation

Goal: confirm bounded random output is available only under the reviewed rules.

Sequence:

1. Authenticate as administrator or key manager
2. Send `GenerateRandom` requesting the maximum allowed size
3. Retry with `requested_len = 0`
4. Retry without an authorized session

Expected outcomes:

- authorized bounded requests return exactly the requested output length
- zero-length and unauthorized requests are denied
- backend failure returns an explicit error and no partial output

## 5. Validate Wrapped Key Import Controls

Goal: prove wrapped import is bounded and cannot become a plaintext export path.

Sequence:

1. Authenticate as key manager
2. Send `ImportWrappedKey` with an approved wrapping key and valid envelope
3. Reauthenticate if the key-manager session has expired during earlier crypto
   operations
4. List keys and read metadata back to confirm the imported key was recorded
5. Retry with a malformed envelope
6. Retry with a destination policy marked exportable

Expected outcomes:

- approved import creates a managed key and returns non-secret metadata only
- post-import readback succeeds only under a live authorized session
- malformed envelopes and forbidden destination policy are denied
- no plaintext key bytes appear in responses or logs

## 6. Validate Explicit High-Risk Denials

Goal: confirm excluded operation classes remain unavailable.

Sequence:

1. Attempt a request using an unsupported algorithm for `SignDetached`
2. Attempt command codes `0x93`, `0x94`, `0x95`, and `0x96`

Expected outcomes:

- unsupported algorithm combinations are denied explicitly
- excluded high-risk commands are absent from capability discovery and fail
  closed if invoked

## 7. Validate Buffer Hygiene and Failure Behavior

Goal: confirm secret-bearing paths stay bounded and fail closed.

Sequence:

1. Send malformed signing and wrapped-import requests around the maximum allowed
   payload size
2. Interrupt an operation after authorization and retry with the same request
   counter
3. Observe only approved command responses and any developer-mode diagnostics

Expected outcomes:

- malformed or interrupted requests do not create partial key state
- replayed privileged requests remain denied
- logs and responses do not reveal key bytes, wrapped plaintext, or reusable
  secret material
