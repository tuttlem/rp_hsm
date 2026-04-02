use rp_hsm::protocol::StatusCode;

use super::key_store_fixtures::{USAGE_SIGN, key_store_status_request, metadata_request, operational_engine, put_key_request};

#[test]
fn interrupted_or_torn_record_puts_store_into_degraded_state() {
    let mut engine = operational_engine();
    let _ = engine.handle_bytes(&put_key_request(
        0x01,
        rp_hsm::protocol::KeyAlgorithm::Ed25519,
        rp_hsm::protocol::KeyOrigin::Generated,
        USAGE_SIGN,
        rp_hsm::protocol::ExportPolicy::NonExportable,
        b"seed-material",
    ));
    let mut snapshot = engine.key_store().snapshot();
    snapshot.journal[0].complete = false;

    let mut rebooted = operational_engine();
    rebooted.restore_key_store(snapshot);
    rebooted.reconcile_boot();

    let status = rebooted.handle_bytes(&key_store_status_request());
    assert_eq!(status.code, StatusCode::Success.as_u8());
    assert_eq!(status.payload.as_slice(), &[0x03, 0x00, 0x08, 0x00, 0x01]);

    let metadata = rebooted.handle_bytes(&metadata_request(0x01));
    assert_eq!(metadata.code, StatusCode::StateError.as_u8());
}
