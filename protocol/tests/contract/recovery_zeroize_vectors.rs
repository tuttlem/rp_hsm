use rp_hsm::protocol::{SessionState, StatusCode, decode_frame, encode_frame};

use crate::lifecycle_fixtures::{
    developer_engine, developer_reset_request, operational_engine, reactivate_recovered_request,
    recovery_request, zeroize_request,
};

#[test]
fn zeroize_returns_completion_flags() {
    let mut engine = operational_engine();
    let response = engine.handle_bytes(&zeroize_request());
    let maybe_encoded = encode_frame(&response);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(decoded.payload.as_slice(), &[0x06, 0x01, 0x01, 0x01, 0x01]);
}

#[test]
fn developer_reset_contract_is_hidden_from_production_but_available_in_developer_mode() {
    let mut engine = operational_engine();
    let denied = engine.handle_bytes(&developer_reset_request());
    assert_eq!(denied.code, StatusCode::CommandError.as_u8());

    let mut developer = developer_engine();
    let allowed = developer.handle_bytes(&developer_reset_request());
    let maybe_encoded = encode_frame(&allowed);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(decoded.payload.as_slice(), &[0x01, 0x01, 0x01, 0x01]);
}

#[test]
fn recovery_returns_restricted_state_vector() {
    let mut engine = operational_engine();
    let _ = engine.handle_bytes(&crate::lifecycle_fixtures::encode_request(0x82, 0x02, &[0x21]));
    engine.set_session_state(SessionState::Recovery);
    let response = engine.handle_bytes(&recovery_request());
    let maybe_encoded = encode_frame(&response);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(decoded.payload.as_slice(), &[0x05, 0x01]);
}

#[test]
fn recovery_reactivation_returns_operational_state_vector() {
    let mut engine = operational_engine();
    let _ = engine.handle_bytes(&crate::lifecycle_fixtures::encode_request(0x82, 0x02, &[0x21]));
    engine.set_session_state(SessionState::Recovery);
    let _ = engine.handle_bytes(&recovery_request());
    let recover = engine.handle_bytes(&crate::lifecycle_fixtures::recover_to_provisioned_request());
    assert_eq!(recover.code, StatusCode::Success.as_u8());
    let reactivation_id = [
        recover.payload[1],
        recover.payload[2],
        recover.payload[3],
        recover.payload[4],
    ];
    let response = engine.handle_bytes(&reactivate_recovered_request(reactivation_id));
    let maybe_encoded = encode_frame(&response);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(decoded.payload.as_slice()[0], 0x03);
}
