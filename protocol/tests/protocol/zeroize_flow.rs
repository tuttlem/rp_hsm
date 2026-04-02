use rp_hsm::protocol::StatusCode;

use super::lifecycle_fixtures::{operational_engine, zeroize_request};

#[test]
fn zeroize_clears_owner_state_and_requires_reprovisioning() {
    let mut engine = operational_engine();
    let response = engine.handle_bytes(&zeroize_request());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.as_slice(), &[0x06, 0x01, 0x01, 0x01, 0x01]);
}

#[test]
fn repeated_zeroize_is_denied_after_success() {
    let mut engine = operational_engine();
    let ok = engine.handle_bytes(&zeroize_request());
    assert_eq!(ok.code, StatusCode::Success.as_u8());
    let repeated = engine.handle_bytes(&zeroize_request());
    assert_eq!(repeated.code, StatusCode::StateError.as_u8());
}
