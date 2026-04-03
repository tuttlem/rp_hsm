use host_tools::{DiscoveredDevice, resolve_device_selector};

fn dev(path: &str) -> DiscoveredDevice {
    DiscoveredDevice {
        device_path: path.into(),
        protocol_version: 1,
        device_state: 3,
        session_state: 5,
        developer_mode_present: true,
    }
}

#[test]
fn explicit_device_must_match_compatible_target() {
    let err = resolve_device_selector(Some("/dev/ttyACM9"), &[dev("/dev/ttyACM0")])
        .expect_err("must fail");
    assert!(err.message.contains("re-enumerated") || err.message.contains("incompatible"));
}

#[test]
fn implicit_selection_fails_closed_on_multiple_devices() {
    let err = resolve_device_selector(None, &[dev("/dev/ttyACM0"), dev("/dev/ttyACM1")])
        .expect_err("must fail");
    assert!(err.message.contains("specify --device explicitly"));
}
