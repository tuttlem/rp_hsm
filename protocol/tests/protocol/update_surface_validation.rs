use rp_hsm::protocol::{
    AcceptedFirmwareState, BootSlotMetadata, BootSlotState, BootSlotId, DeviceState, ProtocolEngine,
    RecoveryState, SessionState, StatusCode, TrustedBootState, UpdateRecoveryReason,
    UpdateTransferPhase, UpdateTransferState, default_boot_slots,
};

use super::update_fixtures::{authorized, provisioned_admin_engine, request};

#[test]
fn malformed_update_begin_and_oversized_chunk_are_rejected() {
    let (mut engine, session) = provisioned_admin_engine();
    let malformed = engine.handle_bytes(&request(0x99, 0x02, &authorized(session, 2, &[0x01])));
    assert_eq!(malformed.code, StatusCode::ValidationError.as_u8());

    let mut payload = std::vec::Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&129u16.to_le_bytes());
    payload.extend_from_slice(&[0x55; 129]);
    let oversized = engine.handle_bytes(&request(0x9a, 0x02, &authorized(session, 3, &payload)));
    assert_eq!(oversized.code, StatusCode::ValidationError.as_u8());
}

#[test]
fn ambiguous_activation_restore_enters_recovery() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Developer);
    engine.set_developer_mode(true);
    let accepted = AcceptedFirmwareState {
        trusted_boot_state: TrustedBootState::RecoveryRequired,
        recovery_required: true,
        ..AcceptedFirmwareState::default()
    };
    let mut slots = default_boot_slots(accepted);
    slots[1] = BootSlotMetadata::new(BootSlotId::B, BootSlotState::StagedValidated);
    let transfer = UpdateTransferState {
        phase: UpdateTransferPhase::ActivationPending,
        ..UpdateTransferState::default()
    };
    let recovery = RecoveryState {
        reason: UpdateRecoveryReason::AmbiguousActivation,
        last_trusted_slot: BootSlotId::A,
        staged_slot: BootSlotId::B,
        staged_slot_present: true,
        authorization_required: true,
    };
    engine.restore_firmware_update_state(accepted, slots, transfer, recovery);
    engine.reconcile_boot();
    let status = engine.handle_bytes(&request(0x04, 0x00, &[]));
    assert_eq!(status.code, StatusCode::Success.as_u8());
    assert_eq!(status.payload[0], 0x05);
}
