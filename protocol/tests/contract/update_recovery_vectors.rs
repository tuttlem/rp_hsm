use rp_hsm::protocol::{
    BootSlotId, FirmwareRecoveryResult, FirmwareVersion, encode_firmware_recovery_payload,
};

#[test]
fn recovery_payload_reports_slot_version_and_clear_state() {
    let payload = encode_firmware_recovery_payload(FirmwareRecoveryResult {
        restored_slot: BootSlotId::A,
        restored_version: FirmwareVersion::new(1, 0, 0, 0),
        recovery_required: false,
    });
    assert_eq!(payload.len(), 10);
    assert_eq!(payload[0], 0x01);
    assert_eq!(payload[9], 0x00);
}
