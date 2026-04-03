use rp_hsm::protocol::{StatusCode, decode_frame};

use super::lifecycle_fixtures::{encode_request, operational_engine};

#[test]
fn invalid_transition_from_operational_is_rejected() {
    let mut engine = operational_engine();
    let response = engine.handle_bytes(&encode_request(0x81, 0x02, &[0, 0, 0, 0, 0xa5]));
    assert_eq!(response.code, StatusCode::ValidationError.as_u8());
}

#[test]
fn invalid_target_does_not_change_state() {
    let mut engine = operational_engine();
    let response = engine.handle_bytes(&encode_request(0x85, 0x02, &[0xc3]));
    assert_eq!(response.code, StatusCode::ValidationError.as_u8());
    let lifecycle = engine.handle_bytes(&super::lifecycle_fixtures::lifecycle_status_request());
    let maybe_encoded = rp_hsm::protocol::encode_frame(&lifecycle);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.payload.as_slice(), &[0x03, 0x00, 0x00, 0x00]);
}
