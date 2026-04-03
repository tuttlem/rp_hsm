use rp_hsm::protocol::StatusCode;

use super::crypto_fixtures::{begin_auth, complete_auth, random_request, request, unauthenticated_operational_engine};

#[test]
fn authorized_random_generation_returns_exact_length() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    let response = engine.handle_bytes(&random_request(session, 2, 64));
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload[0], 64);
    assert_eq!(response.payload.len(), 65);
}

#[test]
fn unauthorized_or_invalid_random_requests_are_denied() {
    let mut engine = unauthenticated_operational_engine();
    let unauthorized = engine.handle_bytes(&request(0x91, 0x02, &super::crypto_fixtures::authorized([0; 4], 1, &[32])));
    assert_eq!(unauthorized.code, StatusCode::AuthorizationError.as_u8());

    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");
    let zero_len = engine.handle_bytes(&random_request(session, 2, 0));
    assert_eq!(zero_len.code, StatusCode::ValidationError.as_u8());
}

#[test]
fn unhealthy_rng_fails_closed() {
    let mut engine = unauthenticated_operational_engine();
    engine.set_rng_health(false);
    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    let response = engine.handle_bytes(&random_request(session, 2, 8));
    assert_eq!(response.code, StatusCode::InternalError.as_u8());
}
