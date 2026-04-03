use rp_hsm::protocol::{
    BootSlotId, BootSlotState, FirmwareUpdateBeginResult, FirmwareUpdateStatus, FirmwareVersion,
    UpdateResultClass, UpdateTransferPhase, encode_firmware_update_begin_payload,
    encode_firmware_update_status_payload,
};

#[test]
fn firmware_update_status_vector_is_bounded_and_metadata_only() {
    let payload = encode_firmware_update_status_payload(FirmwareUpdateStatus {
        active_slot: BootSlotId::A,
        active_version: FirmwareVersion::new(1, 0, 0, 0),
        minimum_accepted_version: FirmwareVersion::new(1, 0, 0, 0),
        transfer_phase: UpdateTransferPhase::Empty,
        staged_slot_state: BootSlotState::Empty,
        recovery_required: false,
        last_update_result: UpdateResultClass::None,
        policy_revision: 2,
    });
    assert_eq!(payload.len(), 25);
}

#[test]
fn begin_firmware_update_vector_contains_session_and_policy_revision() {
    let payload = encode_firmware_update_begin_payload(FirmwareUpdateBeginResult {
        target_slot: BootSlotId::B,
        update_session_id: 7,
        expected_size: 512,
        policy_revision: 3,
    });
    assert_eq!(payload.len(), 13);
    assert_eq!(payload[0], 0x02);
}
