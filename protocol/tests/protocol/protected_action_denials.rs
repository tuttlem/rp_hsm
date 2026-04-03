use rp_hsm::protocol::{DeviceState, PolicyProfile, ProtocolEngine, SessionState, StatusCode};

use super::crypto_fixtures::{begin_auth, complete_auth, install_signing_key, request};

fn authorized(session_id: [u8; 4], counter: u32, inner: &[u8]) -> Vec<u8> {
    let mut payload = Vec::from(session_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.extend_from_slice(inner);
    payload
}

#[test]
fn destructive_key_action_requires_additional_approval_when_enabled() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let profile = PolicyProfile {
        dual_control_enabled: true,
        ..PolicyProfile::default()
    };
    engine.restore_policy_profile(profile);

    let challenge_one = begin_auth(&mut engine, 0x06);
    let session_one = complete_auth(&mut engine, challenge_one, 1, b"KEYMG");
    install_signing_key(&mut engine, session_one, 2, 0x01);

    let first = engine.handle_bytes(&request(
        0x8d,
        0x02,
        &authorized(session_one, 3, &[0x01, 0xde, 0xad]),
    ));
    assert_eq!(first.code, StatusCode::AuthorizationError.as_u8());
    assert_eq!(first.payload[0], 0x05);
}
