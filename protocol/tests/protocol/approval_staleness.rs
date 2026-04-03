use rp_hsm::protocol::{DeviceState, PolicyProfile, ProtocolEngine, SessionState, StatusCode};

use super::crypto_fixtures::{begin_auth, complete_auth, request};

fn authorized(session_id: [u8; 4], counter: u32, inner: &[u8]) -> Vec<u8> {
    let mut payload = Vec::from(session_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.extend_from_slice(inner);
    payload
}

#[test]
fn pending_approval_becomes_stale_after_policy_revision_change() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let profile = PolicyProfile {
        dual_control_enabled: true,
        ..PolicyProfile::default()
    };
    engine.restore_policy_profile(profile);

    let challenge_one = begin_auth(&mut engine, 0x03);
    let session_one = complete_auth(&mut engine, challenge_one, 1, b"ADMIN");
    let first = engine.handle_bytes(&request(
        0x87,
        0x02,
        &authorized(session_one, 2, &[0xde, 0xad]),
    ));
    assert_eq!(first.code, StatusCode::AuthorizationError.as_u8());
    assert_eq!(first.payload[0], 0x05);

    let mut revised = engine.policy_profile();
    revised.policy_revision = revised.policy_revision.saturating_add(1);
    engine.restore_policy_profile(revised);

    let challenge_two = begin_auth(&mut engine, 0x03);
    let session_two = complete_auth(&mut engine, challenge_two, 1, b"ADMIN");
    let denied = engine.handle_bytes(&request(
        0x87,
        0x02,
        &authorized(session_two, 2, &[0xde, 0xad]),
    ));
    assert_eq!(denied.code, StatusCode::AuthorizationError.as_u8());
    assert_eq!(denied.payload[0], 0x06);
}
