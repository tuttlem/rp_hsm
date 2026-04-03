use host_tools::{CliError, ErrorKind, ExitStatus, TransportCondition, no_compatible_devices_message};

#[test]
fn busy_port_transport_errors_are_machine_classified() {
    let err = CliError::transport_with_condition(
        "failed to open /dev/ttyACM0: device or resource busy",
        TransportCondition::BusyPort,
    );
    assert_eq!(err.exit_status, ExitStatus::Transport);
    assert_eq!(err.kind, ErrorKind::Transport);
    assert_eq!(err.transport_condition, Some(TransportCondition::BusyPort));
}

#[test]
fn no_device_message_is_actionable() {
    assert!(no_compatible_devices_message().contains("ModemManager"));
    assert!(no_compatible_devices_message().contains("permissions"));
}
