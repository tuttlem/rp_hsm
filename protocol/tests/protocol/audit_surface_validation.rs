use rp_hsm::protocol::{DeviceState, ProtocolEngine, SessionState, StatusCode};

use super::crypto_fixtures::{authorized, begin_auth, complete_auth, request};

#[test]
fn malformed_audit_page_request_is_rejected() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    let response = engine.handle_bytes(&request(0x0d, 0x02, &authorized(session, 2, &[0x00, 0x01])));
    assert_eq!(response.code, StatusCode::ValidationError.as_u8());
}
