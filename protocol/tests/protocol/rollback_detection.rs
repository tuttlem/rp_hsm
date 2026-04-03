use rp_hsm::protocol::StatusCode;

use super::key_store_fixtures::{USAGE_SIGN, key_store_status_request, operational_engine, put_key_request};

#[test]
fn stale_anchor_causes_recovery_required_status() {
    let mut engine = operational_engine();
    let _ = engine.handle_bytes(&put_key_request(
        0x05,
        rp_hsm::protocol::KeyAlgorithm::Ed25519,
        rp_hsm::protocol::KeyOrigin::Generated,
        USAGE_SIGN,
        rp_hsm::protocol::ExportPolicy::NonExportable,
        b"seed-material",
    ));

    let mut snapshot = engine.key_store().snapshot();
    snapshot.anchor.accepted_store_epoch = 0;
    snapshot.anchor.refresh_integrity();

    let mut rebooted = operational_engine();
    rebooted.restore_key_store(snapshot);
    rebooted.reconcile_boot();

    let status = rebooted.handle_bytes(&key_store_status_request());
    assert_eq!(status.code, StatusCode::Success.as_u8());
    assert_eq!(status.payload.as_slice(), &[0x04, 0x01, 0x07, 0x01, 0x00]);
}
