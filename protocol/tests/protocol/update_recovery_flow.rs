use rp_hsm::protocol::{StatusCode, decode_frame};

use super::update_fixtures::{authorized, begin_update, provisioned_admin_engine, recovery_engine, request};

#[test]
fn interrupted_transfer_aborts_to_trusted_state_and_recovery_can_restore_trusted_slot() {
    let (mut engine, session) = provisioned_admin_engine();
    let image = b"firmware-image-v2";
    let begin = begin_update(&mut engine, session, 2, (1, 0, 1, 0), image);
    assert_eq!(begin.code, StatusCode::Success.as_u8());
    let session_id = u32::from_le_bytes(begin.payload[1..5].try_into().unwrap_or([0; 4]));

    let mut chunk = std::vec::Vec::new();
    chunk.extend_from_slice(&session_id.to_le_bytes());
    chunk.extend_from_slice(&0u32.to_le_bytes());
    chunk.extend_from_slice(&4u16.to_le_bytes());
    chunk.extend_from_slice(&image[..4]);
    let transfer = engine.handle_bytes(&request(0x9a, 0x02, &authorized(session, 3, &chunk)));
    assert_eq!(transfer.code, StatusCode::Success.as_u8());

    engine.reconcile_boot();
    assert_eq!(engine.update_transfer_state().phase as u8, 0x06);

    let (mut recovery_engine, recovery_session) = recovery_engine();
    let recover = recovery_engine.handle_bytes(&request(0x9e, 0x02, &authorized(recovery_session, 2, &[0xc3])));
    assert_eq!(recover.code, StatusCode::Success.as_u8());
    let decoded = decode_frame(&rp_hsm::protocol::encode_frame(&recover).unwrap_or_default()).unwrap_or_default();
    assert_eq!(decoded.payload[9], 0x00);
}
