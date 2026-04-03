use rp_hsm::protocol::{ExportPolicy, KeyAlgorithm, KeyOrigin, StatusCode};

use super::key_store_fixtures::{
    USAGE_SIGN, key_store_status_request, metadata_request, operational_engine, put_key_request,
};

#[test]
fn persistent_key_survives_reconstruction_with_same_metadata() {
    let mut engine = operational_engine();
    let put = engine.handle_bytes(&put_key_request(
        0x01,
        KeyAlgorithm::Ed25519,
        KeyOrigin::Generated,
        USAGE_SIGN,
        ExportPolicy::NonExportable,
        b"seed-material",
    ));
    assert_eq!(put.code, StatusCode::Success.as_u8());

    let snapshot = engine.key_store().snapshot();
    let mut rebooted = operational_engine();
    rebooted.restore_key_store(snapshot);
    rebooted.reconcile_boot();

    let status = rebooted.handle_bytes(&key_store_status_request());
    assert_eq!(status.code, StatusCode::Success.as_u8());
    assert_eq!(status.payload.as_slice(), &[0x02, 0x01, 0x07, 0x00, 0x00]);

    let metadata = rebooted.handle_bytes(&metadata_request(0x01));
    assert_eq!(metadata.code, StatusCode::Success.as_u8());
    assert_eq!(metadata.payload.as_slice()[..6], [0x01, 0x01, 0x01, USAGE_SIGN, 0x01, 0x02]);
}
