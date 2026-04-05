use rp_hsm::protocol::{KeyAlgorithm, StatusCode, USAGE_ENCRYPT, USAGE_SIGN};

use super::crypto_fixtures::{
    begin_auth, complete_auth, generate_key_request, request, unauthenticated_operational_engine,
};

#[test]
fn generated_x25519_key_exposes_public_material() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");

    let generated = engine.handle_bytes(&generate_key_request(
        session,
        2,
        KeyAlgorithm::X25519ChaCha20Poly1305,
        USAGE_ENCRYPT | rp_hsm::protocol::USAGE_DECRYPT,
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
}

#[test]
fn generated_x25519_key_rejects_wrong_usage_mask() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");

    let denied = engine.handle_bytes(&generate_key_request(
        session,
        2,
        KeyAlgorithm::X25519ChaCha20Poly1305,
        USAGE_SIGN,
    ));
    assert_eq!(denied.code, StatusCode::AuthorizationError.as_u8());
}
