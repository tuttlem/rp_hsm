use rp_hsm::protocol::StatusCode;

use super::lifecycle_fixtures::{
    begin_provisioning, factory_engine, finalize_request_from_begin_payload, lifecycle_status_request,
};

#[test]
fn interrupted_finalize_reconciles_to_provisioned() {
    let mut engine = factory_engine();
    let begin = begin_provisioning(&mut engine, b"owner-b");
    let begin_payload = super::lifecycle_fixtures::payload(&begin);

    engine.reconcile_boot();
    let lifecycle = engine.handle_bytes(&lifecycle_status_request());
    assert_eq!(lifecycle.payload.as_slice(), &[0x02, 0x01, 0x00, 0x00]);

    let finalize = finalize_request_from_begin_payload(&begin_payload);
    let response = engine.handle_bytes(&finalize);
    assert_eq!(response.code, StatusCode::StateError.as_u8());
}
