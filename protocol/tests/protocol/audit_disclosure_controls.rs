use rp_hsm::protocol::{DeviceState, ProtocolEngine, SessionState, StatusCode};

use super::crypto_fixtures::{authorized, begin_auth, complete_auth, request};

#[test]
fn unauthorized_audit_retrieval_is_denied() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let denied = engine.handle_bytes(&request(
        0x0d,
        0x02,
        &authorized([0, 0, 0, 0], 1, &[0, 0, 0, 0, 4]),
    ));
    assert_eq!(denied.code, StatusCode::AuthorizationError.as_u8());
}

#[test]
fn malformed_audit_page_request_is_validation_error() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    let malformed = engine.handle_bytes(&request(0x0d, 0x02, &authorized(session, 2, &[0x01])));
    assert_eq!(malformed.code, StatusCode::ValidationError.as_u8());
}

#[test]
fn audit_event_details_are_bounded_and_non_secret() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let _ = engine.handle_bytes(&request(0x0c, 0x00, &[]));
    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    let page = engine.handle_bytes(&request(
        0x0d,
        0x02,
        &authorized(session, 2, &[0, 0, 0, 0, 4]),
    ));
    assert_eq!(page.code, StatusCode::Success.as_u8());
    assert!(!page.payload.as_slice().windows(5).any(|window| window == b"ADMIN"));
    assert!(!page.payload.as_slice().windows(4).any(|window| window == b"BOOT"));
}
