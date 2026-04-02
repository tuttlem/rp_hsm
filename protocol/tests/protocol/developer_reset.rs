use rp_hsm::protocol::{DeviceState, ProtocolEngine, SessionState, StatusCode};

use super::lifecycle_fixtures::{developer_engine, developer_reset_request, lifecycle_status_request};

#[test]
fn developer_reset_is_available_only_in_developer_mode() {
    let mut production_engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Developer);
    let denied = production_engine.handle_bytes(&developer_reset_request());
    assert_eq!(denied.code, StatusCode::CommandError.as_u8());

    let mut developer_engine = developer_engine();
    let allowed = developer_engine.handle_bytes(&developer_reset_request());
    assert_eq!(allowed.code, StatusCode::Success.as_u8());
    assert_eq!(allowed.payload.as_slice(), &[0x01, 0x01, 0x01, 0x01]);
}

#[test]
fn developer_reset_returns_device_to_factory() {
    let mut engine = developer_engine();
    let _ = super::lifecycle_fixtures::begin_provisioning(&mut engine, b"dev");
    let response = engine.handle_bytes(&developer_reset_request());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    let lifecycle = engine.handle_bytes(&lifecycle_status_request());
    assert_eq!(lifecycle.payload.as_slice(), &[0x01, 0x00, 0x00, 0x00]);
}
