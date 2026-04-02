use rp_hsm::protocol::StatusCode;

use super::key_store_fixtures::{
    USAGE_SIGN, destroy_key_request, metadata_request, operational_engine, put_key_request,
    revoke_key_request,
};

#[test]
fn revoke_and_destroy_are_explicit_and_repeated_actions_are_denied() {
    let mut engine = operational_engine();
    let _ = engine.handle_bytes(&put_key_request(
        0x02,
        rp_hsm::protocol::KeyAlgorithm::P256,
        rp_hsm::protocol::KeyOrigin::Imported,
        USAGE_SIGN,
        rp_hsm::protocol::ExportPolicy::WrappedOnly,
        b"wrapped-key",
    ));

    let revoke = engine.handle_bytes(&revoke_key_request(0x02));
    assert_eq!(revoke.code, StatusCode::Success.as_u8());
    let revoke_again = engine.handle_bytes(&revoke_key_request(0x02));
    assert_eq!(revoke_again.code, StatusCode::ReplayError.as_u8());

    let metadata = engine.handle_bytes(&metadata_request(0x02));
    assert_eq!(metadata.code, StatusCode::Success.as_u8());
    assert_eq!(metadata.payload.as_slice()[5], 0x03);

    let destroy = engine.handle_bytes(&destroy_key_request(0x02));
    assert_eq!(destroy.code, StatusCode::Success.as_u8());
    let destroy_again = engine.handle_bytes(&destroy_key_request(0x02));
    assert_eq!(destroy_again.code, StatusCode::ReplayError.as_u8());
}
