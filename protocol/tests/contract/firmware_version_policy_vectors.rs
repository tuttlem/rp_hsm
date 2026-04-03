use rp_hsm::protocol::{AcceptedFirmwareState, FirmwareVersion, firmware_version_allowed};

#[test]
fn firmware_version_ordering_enforces_floor_and_forward_progression() {
    let accepted = AcceptedFirmwareState::default();
    assert!(firmware_version_allowed(FirmwareVersion::new(1, 0, 1, 0), accepted).is_ok());
    assert!(firmware_version_allowed(FirmwareVersion::new(1, 0, 0, 0), accepted).is_err());
    assert!(firmware_version_allowed(FirmwareVersion::new(0, 9, 9, 9), accepted).is_err());
}
