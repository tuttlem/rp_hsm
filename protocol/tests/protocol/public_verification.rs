use rp_hsm::protocol::{KeyAlgorithm, StatusCode};

use super::crypto_fixtures::{request, sign_message_with_seed, unauthenticated_operational_engine, verify_request};

#[test]
fn verify_detached_returns_true_for_valid_ed25519_signature() {
    let mut engine = unauthenticated_operational_engine();
    let signature = sign_message_with_seed(b"verify me");
    let public_key = rp_hsm::protocol::ed25519_public_key_from_seed(&super::crypto_fixtures::ED25519_SEED)
        .unwrap_or([0; 32]);
    let response = engine.handle_bytes(&verify_request(
        KeyAlgorithm::Ed25519,
        b"verify me",
        &public_key,
        &signature,
    ));
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.as_slice(), &[0x01]);
}

#[test]
fn verify_detached_returns_false_for_modified_signature() {
    let mut engine = unauthenticated_operational_engine();
    let mut signature = sign_message_with_seed(b"verify me");
    signature[0] ^= 0x55;
    let public_key = rp_hsm::protocol::ed25519_public_key_from_seed(&super::crypto_fixtures::ED25519_SEED)
        .unwrap_or([0; 32]);
    let response = engine.handle_bytes(&verify_request(
        KeyAlgorithm::Ed25519,
        b"verify me",
        &public_key,
        &signature,
    ));
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.as_slice(), &[0x00]);
}

#[test]
fn malformed_verify_request_is_denied() {
    let mut engine = unauthenticated_operational_engine();
    let response = engine.handle_bytes(&request(0x0b, 0x00, &[0x01, 0x05, 0x00, b'h', b'e']));
    assert_eq!(response.code, StatusCode::ValidationError.as_u8());
}
