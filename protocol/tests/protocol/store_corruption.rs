use rp_hsm::protocol::StatusCode;

use super::key_store_fixtures::{USAGE_SIGN, key_store_status_request, operational_engine, put_key_request};

#[test]
fn duplicate_highest_revision_with_conflicting_payloads_marks_store_corrupt() {
    let mut engine = operational_engine();
    let _ = engine.handle_bytes(&put_key_request(
        0x04,
        rp_hsm::protocol::KeyAlgorithm::Ed25519,
        rp_hsm::protocol::KeyOrigin::Generated,
        USAGE_SIGN,
        rp_hsm::protocol::ExportPolicy::NonExportable,
        b"seed-material",
    ));

    let mut snapshot = engine.key_store().snapshot();
    let mut conflicting = snapshot.journal[0].clone();
    conflicting.material.material_bytes[0] ^= 0x01;
    conflicting.refresh_integrity();
    let _ = snapshot.journal.push(conflicting);

    let mut rebooted = operational_engine();
    rebooted.restore_key_store(snapshot);
    rebooted.reconcile_boot();

    let status = rebooted.handle_bytes(&key_store_status_request());
    assert_eq!(status.code, StatusCode::Success.as_u8());
    assert_eq!(status.payload.as_slice(), &[0x03, 0x01, 0x07, 0x00, 0x01]);
}
