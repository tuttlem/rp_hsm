use rp_hsm::protocol::{StatusCode, decode_frame};

use super::lifecycle_fixtures::{
    begin_provisioning, factory_engine, finalize_request_from_begin_payload, lifecycle_status_request,
};

#[test]
fn provisioning_moves_factory_to_operational() {
    let mut engine = factory_engine();

    let begin = begin_provisioning(&mut engine, b"lab-owner");
    let begin_frame = decode_frame(&begin);
    assert!(begin_frame.is_ok());
    let begin_frame = begin_frame.unwrap_or_default();
    assert_eq!(begin_frame.code, StatusCode::Success.as_u8());
    let begin_payload: Vec<u8> = begin_frame.payload.into_iter().collect();
    assert_eq!(begin_payload[0], 0x02);

    let finalize = finalize_request_from_begin_payload(&begin_payload);
    let finalize_response = engine.handle_bytes(&finalize);
    assert_eq!(finalize_response.code, StatusCode::Success.as_u8());
    assert_eq!(finalize_response.payload.as_slice()[0], 0x03);

    let lifecycle = engine.handle_bytes(&lifecycle_status_request());
    assert_eq!(lifecycle.payload.as_slice(), &[0x03, 0x01, 0x00, 0x00]);
}

#[test]
fn malformed_begin_provisioning_is_rejected() {
    let mut engine = factory_engine();
    let response = engine.handle_bytes(&super::lifecycle_fixtures::encode_request(0x80, 0x02, &[]));
    assert_eq!(response.code, StatusCode::ValidationError.as_u8());
    let lifecycle_response = engine.handle_bytes(&lifecycle_status_request());
    let maybe_encoded = rp_hsm::protocol::encode_frame(&lifecycle_response);
    assert!(maybe_encoded.is_some());
    let lifecycle = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(lifecycle.is_ok());
    let lifecycle = lifecycle.unwrap_or_default();
    assert_eq!(lifecycle.payload.as_slice(), &[0x01, 0x00, 0x00, 0x00]);
}

#[test]
fn repeated_finalize_is_rejected() {
    let mut engine = factory_engine();
    let begin = begin_provisioning(&mut engine, b"owner-a");
    let begin_payload = super::lifecycle_fixtures::payload(&begin);
    let finalize = finalize_request_from_begin_payload(&begin_payload);
    let ok = engine.handle_bytes(&finalize);
    assert_eq!(ok.code, StatusCode::Success.as_u8());
    let repeated = engine.handle_bytes(&finalize);
    assert_eq!(repeated.code, StatusCode::StateError.as_u8());
}
