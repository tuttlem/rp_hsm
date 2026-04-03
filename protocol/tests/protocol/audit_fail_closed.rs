use rp_hsm::protocol::{DeviceState, ProtocolEngine, SessionState, StatusCode};

use super::crypto_fixtures::{authorized, begin_auth, complete_auth, request};

#[test]
fn corrupted_audit_restore_locks_retrieval_and_sets_degraded_health() {
    let mut seed = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let _ = seed.handle_bytes(&request(0x0c, 0x00, &[]));
    let mut snapshot = seed.audit_snapshot();
    snapshot.events[0].integrity_tag ^= 0x55;

    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    engine.restore_audit_snapshot(snapshot);
    engine.reconcile_boot();

    let health = engine.handle_bytes(&request(0x0c, 0x00, &[]));
    assert_eq!(health.code, StatusCode::Success.as_u8());
    assert_eq!(health.payload[7], 0x05);
    assert_eq!(health.payload[12], 0x01);

    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    let audit = engine.handle_bytes(&request(
        0x0d,
        0x02,
        &authorized(session, 2, &[0, 0, 0, 0, 4]),
    ));
    assert_eq!(audit.code, StatusCode::StateError.as_u8());
}
