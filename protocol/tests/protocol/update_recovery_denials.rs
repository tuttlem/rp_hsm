use rp_hsm::protocol::{DeviceState, ProtocolEngine, SessionState, StatusCode};

use super::update_fixtures::{authorized, provisioned_admin_engine, request};

#[test]
fn recover_trusted_firmware_requires_recovery_state_and_role() {
    let (mut engine, admin_session) = provisioned_admin_engine();
    let denied = engine.handle_bytes(&request(0x9e, 0x02, &authorized(admin_session, 2, &[0xc3])));
    assert_eq!(denied.code, StatusCode::StateError.as_u8());

    let mut recovery_engine = ProtocolEngine::new(DeviceState::Recovery, SessionState::Unauthenticated);
    let denied_unauth = recovery_engine.handle_bytes(&request(0x9e, 0x02, &authorized([0; 4], 1, &[0xc3])));
    assert_eq!(denied_unauth.code, StatusCode::AuthorizationError.as_u8());
}
