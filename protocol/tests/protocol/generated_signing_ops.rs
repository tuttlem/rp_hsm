use rp_hsm::protocol::{KeyAlgorithm, StatusCode, USAGE_SIGN};

use super::crypto_fixtures::{
    begin_auth, complete_auth, generate_key_request, request, sign_request,
    unauthenticated_operational_engine, verify_request,
};

#[test]
fn generated_ed25519_key_signs_and_exposes_public_material() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");

    let generated = engine.handle_bytes(&generate_key_request(
        session,
        2,
        KeyAlgorithm::Ed25519,
        USAGE_SIGN,
    ));
    assert_eq!(generated.code, StatusCode::Success.as_u8());
    let key_id = generated.payload[0];

    let metadata = engine.handle_bytes(&request(
        0x8b,
        0x00,
        &super::crypto_fixtures::authorized(session, 3, &[key_id]),
    ));
    assert_eq!(metadata.code, StatusCode::Success.as_u8());
    let public_len = usize::from(metadata.payload[10]);
    assert_eq!(public_len, 32);
    let public_key = &metadata.payload.as_slice()[11..11 + public_len];

    let signature = engine.handle_bytes(&sign_request(
        session,
        4,
        key_id,
        KeyAlgorithm::Ed25519,
        b"sign me",
    ));
    assert_eq!(signature.code, StatusCode::Success.as_u8());
    let signature_bytes = &signature.payload.as_slice()[2..];

    let verified = engine.handle_bytes(&verify_request(
        KeyAlgorithm::Ed25519,
        b"sign me",
        public_key,
        signature_bytes,
    ));
    assert_eq!(verified.code, StatusCode::Success.as_u8());
    assert_eq!(verified.payload.as_slice(), &[0x01]);
}

#[test]
fn generated_p256_key_signs_and_exposes_public_material() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");

    let generated = engine.handle_bytes(&generate_key_request(
        session,
        2,
        KeyAlgorithm::P256,
        USAGE_SIGN,
    ));
    assert_eq!(generated.code, StatusCode::Success.as_u8());
    let key_id = generated.payload[0];

    let metadata = engine.handle_bytes(&request(
        0x8b,
        0x00,
        &super::crypto_fixtures::authorized(session, 3, &[key_id]),
    ));
    assert_eq!(metadata.code, StatusCode::Success.as_u8());
    let public_len = usize::from(metadata.payload[10]);
    assert_eq!(public_len, 33);
    let public_key = &metadata.payload.as_slice()[11..11 + public_len];

    let signature = engine.handle_bytes(&sign_request(
        session,
        4,
        key_id,
        KeyAlgorithm::P256,
        b"sign me",
    ));
    assert_eq!(signature.code, StatusCode::Success.as_u8());
    let signature_bytes = &signature.payload.as_slice()[2..];

    let verified = engine.handle_bytes(&verify_request(
        KeyAlgorithm::P256,
        b"sign me",
        public_key,
        signature_bytes,
    ));
    assert_eq!(verified.code, StatusCode::Success.as_u8());
    assert_eq!(verified.payload.as_slice(), &[0x01]);
}
