use rp_hsm::protocol::{StatusCode, decode_frame};

use super::crypto_fixtures::{request, unauthenticated_operational_engine};

#[test]
fn malformed_crypto_requests_are_denied() {
    let mut engine = unauthenticated_operational_engine();

    let malformed_verify = engine.handle_bytes(&request(0x0b, 0x00, &[0x01, 0x01]));
    assert_eq!(malformed_verify.code, StatusCode::ValidationError.as_u8());

    let malformed_capabilities = engine.handle_bytes(&request(0x0a, 0x00, &[0x01]));
    assert_eq!(malformed_capabilities.code, StatusCode::ValidationError.as_u8());

    let decoded = decode_frame(&rp_hsm::protocol::encode_frame(&malformed_verify).unwrap_or_default());
    assert!(decoded.is_ok());
}

#[test]
fn unsupported_algorithm_signing_is_denied() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = super::crypto_fixtures::begin_auth(&mut engine, 0x06);
    let session = super::crypto_fixtures::complete_auth(&mut engine, challenge, 1, b"KEYMG");
    super::crypto_fixtures::install_signing_key(&mut engine, session, 2, 0x01);
    let inner = super::crypto_fixtures::authorized(
        session,
        3,
        &[0x01, 0x02, 0x04, 0x00, b't', b'e', b's', b't'],
    );
    let response = engine.handle_bytes(&request(0x90, 0x02, &inner));
    assert_eq!(response.code, StatusCode::AuthorizationError.as_u8());
}
