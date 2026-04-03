use host_tools::{
    CliError, ClientConfig, ErrorKind, ExitStatus, Role, SerialBackend, TransportCondition,
};

#[test]
fn supported_client_surface_exports_core_types() {
    let config = ClientConfig::new("/dev/null".to_string(), 115_200);
    let _backend = SerialBackend::new(config);
    assert_eq!(Role::Administrator.to_wire(), 0x03);
}

#[test]
fn device_denials_and_host_failures_are_distinct() {
    let denial = CliError::auth("device denied the requested operation");
    let busy = CliError::transport_with_condition("busy", TransportCondition::BusyPort);
    assert_eq!(denial.kind, ErrorKind::DeviceDenied);
    assert_eq!(denial.exit_status, ExitStatus::Auth);
    assert_eq!(busy.kind, ErrorKind::Transport);
    assert_eq!(busy.exit_status, ExitStatus::Transport);
}
