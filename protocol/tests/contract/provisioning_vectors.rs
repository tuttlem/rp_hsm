use rp_hsm::protocol::{StatusCode, decode_frame, encode_frame};

use crate::lifecycle_fixtures::{begin_provisioning, factory_engine, finalize_request_from_begin_payload};

#[test]
fn begin_provisioning_returns_transition_identifier() {
    let mut engine = factory_engine();
    let response = engine.handle_bytes(&crate::lifecycle_fixtures::encode_request(0x80, 0x02, b"owner-a"));
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.as_slice()[0], 0x02);
    assert_eq!(response.payload.len(), 9);
}

#[test]
fn finalize_provisioning_returns_operational_state_and_revision() {
    let mut engine = factory_engine();
    let begin = begin_provisioning(&mut engine, b"owner-b");
    let begin_frame = decode_frame(&begin);
    assert!(begin_frame.is_ok());
    let begin_frame = begin_frame.unwrap_or_default();
    let finalize = finalize_request_from_begin_payload(begin_frame.payload.as_slice());
    let response = engine.handle_bytes(&finalize);
    let maybe_encoded = encode_frame(&response);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(decoded.payload.as_slice()[0], 0x03);
}
