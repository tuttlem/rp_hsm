use rp_hsm::protocol::{SessionState, StatusCode, decode_frame};

use super::lifecycle_fixtures::{
    operational_engine, reactivate_recovered_request, recover_to_provisioned_request,
    recovery_request,
};

#[test]
fn recovery_enters_restricted_state_and_requires_explicit_reactivation() {
    let mut engine = operational_engine();
    let lock = engine.handle_bytes(&super::lifecycle_fixtures::encode_request(0x82, 0x02, &[0x42]));
    assert_eq!(lock.code, StatusCode::Success.as_u8());
    engine.set_session_state(SessionState::Recovery);

    let recovery = engine.handle_bytes(&recovery_request());
    assert_eq!(recovery.code, StatusCode::Success.as_u8());
    assert_eq!(recovery.payload.as_slice(), &[0x05, 0x01]);

    let recover = engine.handle_bytes(&recover_to_provisioned_request());
    assert_eq!(recover.code, StatusCode::Success.as_u8());
    assert_eq!(recover.payload.as_slice()[0], 0x02);
    let reactivation_id = [
        recover.payload.as_slice()[1],
        recover.payload.as_slice()[2],
        recover.payload.as_slice()[3],
        recover.payload.as_slice()[4],
    ];

    let lifecycle = engine.handle_bytes(&super::lifecycle_fixtures::lifecycle_status_request());
    let maybe_encoded = rp_hsm::protocol::encode_frame(&lifecycle);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.payload.as_slice(), &[0x02, 0x00, 0x00, 0x01]);

    let reactivate = engine.handle_bytes(&reactivate_recovered_request(reactivation_id));
    assert_eq!(reactivate.code, StatusCode::Success.as_u8());
    assert_eq!(reactivate.payload.as_slice()[0], 0x03);
}
