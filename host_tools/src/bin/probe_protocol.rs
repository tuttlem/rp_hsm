use std::env;
use std::io;
use std::thread;
use std::time::Duration;

use protocol::protocol::{
    FLAG_INCLUDE_RESTRICTED, MessageKind, PROTOCOL_VERSION, ProtocolFrame, StatusCode,
    developer_reset_marker, encode_frame, finalize_marker,
};

const DEFAULT_BAUD: u32 = 115_200;
const DEFAULT_TIMEOUT_MS: u64 = 1_000;
const REBOOT_SETTLE_MS: u64 = 1500;
const RECONNECT_ATTEMPTS: usize = 30;
const FLASH_SETTLE_MS: u64 = 200;
const READ_RETRY_ATTEMPTS: usize = 5;
const READ_RETRY_DELAY_MS: u64 = 150;

type DynError = Box<dyn std::error::Error>;

#[derive(Clone, Debug)]
struct ProbeConfig {
    port_name: String,
    baud: u32,
}

fn main() -> Result<(), DynError> {
    let config = parse_args()?;
    let mut port = open_port(&config)?;

    probe_protocol_version(&mut *port)?;
    port = ensure_factory_baseline(&config, port)?;
    probe_public_catalog(&mut *port)?;
    probe_lifecycle_status(&mut *port, &[0x01, 0x00, 0x00, 0x00])?;
    probe_key_store_status(&mut *port, &[0x01, 0x00, 0x08, 0x00, 0x00])?;

    let transition_id = probe_begin_provisioning(&mut *port)?;
    probe_lifecycle_status(&mut *port, &[0x02, 0x01, 0x00, 0x01])?;
    probe_finalize_provisioning(&mut *port, transition_id)?;
    probe_device_status(&mut *port, &[0x03, 0x05])?;
    probe_lifecycle_status(&mut *port, &[0x03, 0x01, 0x00, 0x00])?;

    probe_put_key(&mut *port, 0x01, b"seed-material")?;
    probe_key_store_status(&mut *port, &[0x02, 0x01, 0x07, 0x00, 0x00])?;
    probe_key_metadata(&mut *port, 0x01, &[0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00])?;
    probe_reboot(&mut *port)?;
    drop(port);

    let mut port = reopen_after_reboot(&config)?;
    probe_device_status(&mut *port, &[0x03, 0x05])?;
    probe_lifecycle_status(&mut *port, &[0x03, 0x01, 0x00, 0x00])?;
    probe_key_store_status(&mut *port, &[0x02, 0x01, 0x07, 0x00, 0x00])?;
    probe_list_single_key(&mut *port, 0x01)?;
    probe_key_metadata(&mut *port, 0x01, &[0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00])?;
    probe_revoke_destroy(&mut *port)?;
    probe_key_store_status(&mut *port, &[0x01, 0x00, 0x08, 0x00, 0x00])?;
    probe_invalid_finalize_in_operational(&mut *port, transition_id)?;
    port = reset_to_factory(&config, port)?;
    let capacity_transition = probe_begin_provisioning(&mut *port)?;
    probe_finalize_provisioning(&mut *port, capacity_transition)?;
    probe_fill_capacity(&mut *port)?;

    port = reset_to_factory(&config, port)?;
    let rollback_transition = probe_begin_provisioning(&mut *port)?;
    probe_finalize_provisioning(&mut *port, rollback_transition)?;
    probe_put_key(&mut *port, 0x01, b"rollback-seed")?;
    probe_store_fault(&mut *port, 0x02)?;
    probe_reboot(&mut *port)?;
    drop(port);

    let mut port = reopen_after_reboot(&config)?;
    probe_device_status(&mut *port, &[0x03, 0x05])?;
    probe_key_store_status(&mut *port, &[0x04, 0x01, 0x07, 0x01, 0x00])?;
    probe_denied_non_ready_queries(&mut *port, 0x01)?;

    port = reset_to_factory(&config, port)?;
    let corruption_transition = probe_begin_provisioning(&mut *port)?;
    probe_finalize_provisioning(&mut *port, corruption_transition)?;
    probe_put_key(&mut *port, 0x01, b"corrupt-seed")?;
    probe_store_fault(&mut *port, 0x01)?;
    probe_reboot(&mut *port)?;
    drop(port);

    let mut port = reopen_after_reboot(&config)?;
    probe_device_status(&mut *port, &[0x05, 0x05])?;
    probe_lifecycle_status(&mut *port, &[0x05, 0x00, 0x01, 0x00])?;
    probe_key_store_status(&mut *port, &[0x03, 0x00, 0x08, 0x00, 0x01])?;
    probe_denied_non_ready_queries(&mut *port, 0x01)?;

    let _port = reset_to_factory(&config, port)?;

    println!(
        "All developer-mode persistent-store probes passed on {}",
        config.port_name
    );
    Ok(())
}

fn parse_args() -> Result<ProbeConfig, DynError> {
    let mut args = env::args().skip(1);
    let mut port_name = String::from("/dev/ttyACM0");
    let mut baud = DEFAULT_BAUD;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --port".into());
                };
                port_name = value;
            }
            "--baud" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --baud".into());
                };
                baud = value.parse::<u32>()?;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument: {other}").into());
            }
        }
    }

    Ok(ProbeConfig { port_name, baud })
}

fn print_help() {
    println!("Usage: cargo probe -- --port /dev/ttyACM0 [--baud 115200]");
}

fn open_port(config: &ProbeConfig) -> Result<Box<dyn serialport::SerialPort>, DynError> {
    let mut port = serialport::new(&config.port_name, config.baud)
        .timeout(Duration::from_millis(DEFAULT_TIMEOUT_MS))
        .open()?;
    port.write_data_terminal_ready(true)?;
    thread::sleep(Duration::from_millis(200));
    Ok(port)
}

fn reopen_after_reboot(config: &ProbeConfig) -> Result<Box<dyn serialport::SerialPort>, DynError> {
    thread::sleep(Duration::from_millis(REBOOT_SETTLE_MS));
    for _ in 0..RECONNECT_ATTEMPTS {
        if let Ok(port) = open_port(config) {
            return Ok(port);
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(format!("device did not re-enumerate on {}", config.port_name).into())
}

fn probe_protocol_version(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(port, "GetProtocolVersion", &request(0x01, 0x00, &[]))?;
    expect_payload(&response, StatusCode::Success, &[PROTOCOL_VERSION])?;
    Ok(())
}

fn ensure_factory_baseline(
    config: &ProbeConfig,
    mut port: Box<dyn serialport::SerialPort>,
) -> Result<Box<dyn serialport::SerialPort>, DynError> {
    let response = exchange(&mut *port, "GetDeviceStatus", &request(0x02, 0x00, &[0x00]))?;
    expect_status(&response, StatusCode::Success)?;
    match response.payload.as_slice() {
        [0x01, 0x05] => Ok(port),
        [_, 0x05] => {
            reset_to_factory(config, port)
        }
        other => Err(format!(
            "unexpected initial device status: expected developer session, got {}",
            hex(other)
        )
        .into()),
    }
}

fn probe_device_status(
    port: &mut dyn serialport::SerialPort,
    expected: &[u8],
) -> Result<(), DynError> {
    let response = exchange(port, "GetDeviceStatus", &request(0x02, 0x00, &[0x00]))?;
    expect_payload(&response, StatusCode::Success, expected)
}

fn probe_public_catalog(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(port, "GetCommandCatalog", &request(0x03, 0x00, &[0x00]))?;
    expect_payload(&response, StatusCode::Success, &[0x05, 0x01, 0x02, 0x03, 0x04, 0x05])?;

    let restricted = exchange(
        port,
        "GetRestrictedCatalog",
        &request(0x03, FLAG_INCLUDE_RESTRICTED, &[0x01]),
    )?;
    expect_catalog_members(
        &restricted,
        StatusCode::Success,
        &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        ],
    )?;
    Ok(())
}

fn probe_lifecycle_status(
    port: &mut dyn serialport::SerialPort,
    expected: &[u8],
) -> Result<(), DynError> {
    let response = exchange(port, "GetLifecycleStatus", &request(0x04, 0x00, &[]))?;
    expect_payload(&response, StatusCode::Success, expected)
}

fn probe_key_store_status(
    port: &mut dyn serialport::SerialPort,
    expected: &[u8],
) -> Result<(), DynError> {
    let response = exchange(port, "GetKeyStoreStatus", &request(0x05, 0x00, &[]))?;
    expect_payload(&response, StatusCode::Success, expected)
}

fn probe_begin_provisioning(port: &mut dyn serialport::SerialPort) -> Result<[u8; 4], DynError> {
    let response = exchange(port, "BeginProvisioning", &request(0x80, 0x02, b"lab"))?;
    expect_status(&response, StatusCode::Success)?;
    if response.payload.len() != 9 || response.payload[0] != 0x02 {
        return Err(format!("unexpected begin payload: {}", hex(response.payload.as_slice())).into());
    }
    settle_after_flash_mutation();
    Ok([
        response.payload[1],
        response.payload[2],
        response.payload[3],
        response.payload[4],
    ])
}

fn probe_finalize_provisioning(
    port: &mut dyn serialport::SerialPort,
    transition_id: [u8; 4],
) -> Result<(), DynError> {
    let finalize = [
        transition_id[0],
        transition_id[1],
        transition_id[2],
        transition_id[3],
        finalize_marker(),
    ];
    let response = exchange(port, "FinalizeProvisioning", &request(0x81, 0x02, &finalize))?;
    expect_status(&response, StatusCode::Success)?;
    if response.payload.first() != Some(&0x03) {
        return Err(format!("unexpected finalize payload: {}", hex(response.payload.as_slice())).into());
    }
    settle_after_flash_mutation();
    Ok(())
}

fn probe_invalid_finalize_in_operational(
    port: &mut dyn serialport::SerialPort,
    transition_id: [u8; 4],
) -> Result<(), DynError> {
    let finalize = [
        transition_id[0],
        transition_id[1],
        transition_id[2],
        transition_id[3],
        finalize_marker(),
    ];
    let response = exchange(
        port,
        "FinalizeProvisioningRejected",
        &request(0x81, 0x02, &finalize),
    )?;
    expect_status(&response, StatusCode::StateError)
}

fn probe_put_key(
    port: &mut dyn serialport::SerialPort,
    key_id: u8,
    material: &[u8],
) -> Result<(), DynError> {
    let mut payload = vec![key_id, 0x01, 0x01, 0x01, 0x01, u8::try_from(material.len())?];
    payload.extend_from_slice(material);
    let response = exchange(port, "PutPersistentKey", &request(0x89, 0x02, &payload))?;
    expect_status(&response, StatusCode::Success)?;
    settle_after_flash_mutation();
    Ok(())
}

fn probe_key_metadata(
    port: &mut dyn serialport::SerialPort,
    key_id: u8,
    expected_payload: &[u8],
) -> Result<(), DynError> {
    let response = exchange(port, "GetKeyMetadata", &request(0x8b, 0x00, &[key_id]))?;
    expect_payload(&response, StatusCode::Success, expected_payload)
}

fn probe_list_single_key(
    port: &mut dyn serialport::SerialPort,
    key_id: u8,
) -> Result<(), DynError> {
    let response = exchange(port, "ListPersistentKeys", &request(0x8a, 0x00, &[]))?;
    expect_payload(
        &response,
        StatusCode::Success,
        &[0x01, key_id, 0x01, 0x02, 0x01, 0x01],
    )
}

fn probe_revoke_destroy(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let revoke = exchange(port, "RevokePersistentKey", &request(0x8c, 0x02, &[0x01, 0x52]))?;
    expect_payload(
        &revoke,
        StatusCode::Success,
        &[0x01, 0x03, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
    )?;
    settle_after_flash_mutation();

    let destroy = exchange(port, "DestroyPersistentKey", &request(0x8d, 0x02, &[0x01, 0xde, 0xad]))?;
    expect_payload(&destroy, StatusCode::Success, &[0x01, 0x05, 0x01, 0x01])?;
    settle_after_flash_mutation();
    Ok(())
}

fn probe_developer_reset(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let marker = developer_reset_marker();
    let response = exchange(port, "DeveloperResetLifecycle", &request(0x88, 0x02, &marker))?;
    expect_payload(&response, StatusCode::Success, &[0x01, 0x01, 0x01, 0x01])?;
    settle_after_flash_mutation();
    Ok(())
}

fn probe_fill_capacity(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    for key_id in 1u8..=8 {
        let material = format!("seed-{key_id:02}");
        probe_put_key(port, key_id, material.as_bytes())?;
    }
    probe_key_store_status(port, &[0x05, 0x08, 0x00, 0x00, 0x00])?;

    let overflow = exchange(
        port,
        "PutPersistentKeyOverflow",
        &request(0x89, 0x02, &[0x09, 0x01, 0x01, 0x01, 0x01, 0x04, b'o', b'v', b'e', b'r']),
    )?;
    expect_status(&overflow, StatusCode::StateError)
}

fn settle_after_flash_mutation() {
    thread::sleep(Duration::from_millis(FLASH_SETTLE_MS));
}

fn verify_factory_empty_state(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    probe_device_status(port, &[0x01, 0x05])?;
    probe_lifecycle_status(port, &[0x01, 0x00, 0x00, 0x00])?;
    probe_key_store_status(port, &[0x01, 0x00, 0x08, 0x00, 0x00])
}

fn reset_to_factory(
    config: &ProbeConfig,
    mut port: Box<dyn serialport::SerialPort>,
) -> Result<Box<dyn serialport::SerialPort>, DynError> {
    probe_developer_reset(&mut *port)?;
    drop(port);
    let mut reopened = reopen_after_reboot(config)?;
    verify_factory_empty_state(&mut *reopened)?;
    Ok(reopened)
}

fn probe_store_fault(
    port: &mut dyn serialport::SerialPort,
    action: u8,
) -> Result<(), DynError> {
    let response = exchange(port, "DeveloperStoreFault", &request(0x8e, 0x02, &[action]))?;
    expect_payload(&response, StatusCode::Success, &[action])
}

fn probe_reboot(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(port, "DeveloperReboot", &request(0x8f, 0x02, b"RST"))?;
    expect_payload(&response, StatusCode::Success, &[])
}

fn probe_denied_non_ready_queries(
    port: &mut dyn serialport::SerialPort,
    key_id: u8,
) -> Result<(), DynError> {
    let list = exchange(port, "ListPersistentKeysDenied", &request(0x8a, 0x00, &[]))?;
    expect_status(&list, StatusCode::StateError)?;
    let metadata = exchange(port, "GetKeyMetadataDenied", &request(0x8b, 0x00, &[key_id]))?;
    expect_status(&metadata, StatusCode::StateError)
}

fn request(code: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, code, flags, payload);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    maybe_encoded.unwrap_or_default().into_iter().collect()
}

fn exchange(
    port: &mut dyn serialport::SerialPort,
    name: &str,
    request: &[u8],
) -> Result<ProtocolFrame, DynError> {
    port.clear(serialport::ClearBuffer::All)?;
    port.write_all(request)?;
    port.flush()?;
    thread::sleep(Duration::from_millis(100));

    let mut header = [0u8; 6];
    read_exact_with_retry(port, &mut header)?;
    let payload_len = usize::from(u16::from_le_bytes([header[4], header[5]]));
    let mut bytes = header.to_vec();
    if payload_len > 0 {
        let mut payload = vec![0u8; payload_len];
        read_exact_with_retry(port, &mut payload)?;
        bytes.extend_from_slice(&payload);
    }

    let decoded = protocol::protocol::decode_frame(&bytes)
        .map_err(|err| format!("{name} decode failed: {err:?}"))?;
    println!("\n{name}");
    println!("tx: {}", hex(request));
    println!("rx: {}", hex(&bytes));
    println!(
        "status: {:02x}, payload: {}",
        decoded.code,
        hex(decoded.payload.as_slice())
    );
    Ok(decoded)
}

fn read_exact_with_retry(
    port: &mut dyn serialport::SerialPort,
    buffer: &mut [u8],
) -> Result<(), DynError> {
    for attempt in 0..READ_RETRY_ATTEMPTS {
        match port.read_exact(buffer) {
            Ok(()) => return Ok(()),
            Err(err)
                if err.kind() == io::ErrorKind::TimedOut
                    && attempt + 1 < READ_RETRY_ATTEMPTS =>
            {
                thread::sleep(Duration::from_millis(READ_RETRY_DELAY_MS));
            }
            Err(err) => return Err(err.into()),
        }
    }

    Err(io::Error::new(io::ErrorKind::TimedOut, "probe receive timed out").into())
}

fn expect_status(response: &ProtocolFrame, expected: StatusCode) -> Result<(), DynError> {
    if response.code != expected.as_u8() {
        return Err(format!(
            "unexpected status: expected {:02x}, got {:02x}",
            expected.as_u8(),
            response.code
        )
        .into());
    }
    Ok(())
}

fn expect_payload(
    response: &ProtocolFrame,
    expected_status: StatusCode,
    expected_payload: &[u8],
) -> Result<(), DynError> {
    expect_status(response, expected_status)?;
    if response.payload.as_slice() != expected_payload {
        return Err(format!(
            "unexpected payload: expected {}, got {}",
            hex(expected_payload),
            hex(response.payload.as_slice())
        )
        .into());
    }
    Ok(())
}

fn expect_catalog_members(
    response: &ProtocolFrame,
    expected_status: StatusCode,
    expected_commands: &[u8],
) -> Result<(), DynError> {
    expect_status(response, expected_status)?;
    let Some((&count, commands)) = response.payload.as_slice().split_first() else {
        return Err("catalog payload missing count".into());
    };
    if usize::from(count) != expected_commands.len() {
        return Err(format!(
            "unexpected catalog size: expected {}, got {}",
            expected_commands.len(),
            count
        )
        .into());
    }

    let mut expected = expected_commands.to_vec();
    let mut actual = commands.to_vec();
    expected.sort_unstable();
    actual.sort_unstable();
    if actual != expected {
        return Err(format!(
            "unexpected catalog members: expected {}, got {}",
            hex(&expected),
            hex(&actual)
        )
        .into());
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
