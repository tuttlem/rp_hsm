use std::env;
use std::thread;
use std::time::Duration;

use protocol::protocol::{
    FLAG_INCLUDE_RESTRICTED, MessageKind, PROTOCOL_VERSION, ProtocolFrame, StatusCode,
    developer_reset_marker, encode_frame, finalize_marker, unlock_marker,
};

const DEFAULT_BAUD: u32 = 115_200;
const DEFAULT_TIMEOUT_MS: u64 = 1_000;
const FLASH_SETTLE_MS: u64 = 200;
const REBOOT_SETTLE_MS: u64 = 1_500;
const RECONNECT_ATTEMPTS: usize = 30;
const READ_RETRY_ATTEMPTS: usize = 20;
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
    probe_unauthenticated_denial(&mut *port)?;

    let bootstrap = authenticate(&mut *port, "Bootstrap", 0x02, b"BOOT")?;
    let transition_id = begin_provisioning(&mut *port, bootstrap, 2)?;
    finalize_provisioning(&mut *port, bootstrap, 3, transition_id)?;
    probe_lifecycle_status(&mut *port, &[0x03, 0x01, 0x00, 0x00])?;

    let admin = authenticate(&mut *port, "Administrator", 0x03, b"ADMIN")?;
    lock_device(&mut *port, admin, 2)?;
    expect_session_inactive(&mut *port)?;
    let admin = authenticate(&mut *port, "AdministratorLocked", 0x03, b"ADMIN")?;
    unlock_device(&mut *port, admin, 2)?;

    let key_manager = authenticate(&mut *port, "KeyManager", 0x06, b"KEYMG")?;
    put_persistent_key(&mut *port, key_manager, 2, 0x01, b"seed-material")?;
    list_persistent_keys(&mut *port, key_manager, 3)?;
    replay_list_denied(&mut *port, key_manager, 3)?;
    invalidate_session(&mut *port, key_manager, 4)?;
    expect_session_inactive(&mut *port)?;

    let key_manager = authenticate(&mut *port, "KeyManagerExpiry", 0x06, b"KEYMG")?;
    for _ in 0..10 {
        let _ = exchange(&mut *port, "TickProtocolVersion", &request(0x01, 0x00, &[]))?;
    }
    let expired = exchange(
        &mut *port,
        "ExpiredListPersistentKeys",
        &request(0x8a, 0x00, &authorized_payload(key_manager, 2, &[])),
    )?;
    expect_status(&expired, StatusCode::AuthorizationError)?;

    for attempt in 1u32..=3 {
        failed_auth_attempt(&mut *port, "AdminWrongProof", 0x03, attempt, b"WRONG")?;
    }
    let locked = exchange(&mut *port, "LockedBeginAuthentication", &request(0x06, 0x00, &[0x03]))?;
    expect_status(&locked, StatusCode::AuthorizationError)?;

    let key_manager = authenticate(&mut *port, "KeyManagerReboot", 0x06, b"KEYMG")?;
    let _ = exchange(
        &mut *port,
        "ListPersistentKeysBeforeReboot",
        &request(0x8a, 0x00, &authorized_payload(key_manager, 2, &[])),
    )?;
    developer_reboot(&mut *port)?;
    drop(port);

    let mut port = reopen_after_reboot(&config)?;
    expect_session_inactive(&mut *port)?;
    let _port = reset_to_factory(&config, port)?;

    println!(
        "All developer-mode authentication and session probes passed on {}",
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
                println!("Usage: cargo probe -- --port /dev/ttyACM0 [--baud 115200]");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    Ok(ProbeConfig { port_name, baud })
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

fn ensure_factory_baseline(
    config: &ProbeConfig,
    mut port: Box<dyn serialport::SerialPort>,
) -> Result<Box<dyn serialport::SerialPort>, DynError> {
    let response = exchange(&mut *port, "GetDeviceStatus", &request(0x02, 0x00, &[0x00]))?;
    expect_status(&response, StatusCode::Success)?;
    if response.payload.len() == 2 && response.payload[1] != 0x05 {
        return Err(format!(
            "device booted with active non-developer session {}; reflash or reboot into a clean developer-mode baseline before probing",
            hex(response.payload.as_slice())
        )
        .into());
    }
    if response.payload.as_slice() != [0x01, 0x05] {
        port = reset_to_factory(config, port)?;
    }
    Ok(port)
}

fn reset_to_factory(
    _config: &ProbeConfig,
    mut port: Box<dyn serialport::SerialPort>,
) -> Result<Box<dyn serialport::SerialPort>, DynError> {
    let response = exchange(
        &mut *port,
        "DeveloperResetLifecycle",
        &request(0x88, 0x02, &developer_reset_marker()),
    )?;
    expect_status(&response, StatusCode::Success)?;
    settle_after_flash_mutation();
    let verify = exchange(&mut *port, "GetDeviceStatus", &request(0x02, 0x00, &[0x00]))?;
    expect_payload(&verify, StatusCode::Success, &[0x01, 0x05])?;
    let session = exchange(&mut *port, "GetSessionStatus", &request(0x08, 0x00, &[]))?;
    expect_payload(&session, StatusCode::Success, &[0x00, 0x05, 0x00, 0x00, 0x00, 0x01])?;
    Ok(port)
}

fn probe_protocol_version(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(port, "GetProtocolVersion", &request(0x01, 0x00, &[]))?;
    expect_payload(&response, StatusCode::Success, &[PROTOCOL_VERSION])
}

fn probe_public_catalog(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(port, "GetCommandCatalog", &request(0x03, 0x00, &[0x00]))?;
    expect_payload(
        &response,
        StatusCode::Success,
        &[0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    )?;
    let restricted = exchange(
        port,
        "GetRestrictedCatalog",
        &request(0x03, FLAG_INCLUDE_RESTRICTED, &[0x01]),
    )?;
    expect_payload(
        &restricted,
        StatusCode::Success,
        &[0x0b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x88, 0x8e, 0x8f],
    )
}

fn probe_unauthenticated_denial(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(
        port,
        "UnauthenticatedBeginProvisioning",
        &request(0x80, 0x02, &authorized_payload([0, 0, 0, 0], 1, b"lab")),
    )?;
    expect_status(&response, StatusCode::AuthorizationError)
}

fn authenticate(
    port: &mut dyn serialport::SerialPort,
    name: &str,
    role: u8,
    proof: &[u8],
) -> Result<[u8; 4], DynError> {
    let begin = exchange(port, &format!("BeginAuthentication{name}"), &request(0x06, 0x00, &[role]))?;
    expect_status(&begin, StatusCode::Success)?;
    let challenge_id: [u8; 4] = begin.payload.as_slice()[0..4].try_into().unwrap_or([0; 4]);
    let mut payload = Vec::from(challenge_id);
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.push(u8::try_from(proof.len())?);
    payload.extend_from_slice(proof);
    let complete = exchange(
        port,
        &format!("CompleteAuthentication{name}"),
        &request(0x07, 0x02, &payload),
    )?;
    expect_status(&complete, StatusCode::Success)?;
    settle_after_flash_mutation();
    Ok(complete.payload.as_slice()[0..4].try_into().unwrap_or([0; 4]))
}

fn failed_auth_attempt(
    port: &mut dyn serialport::SerialPort,
    name: &str,
    role: u8,
    counter: u32,
    proof: &[u8],
) -> Result<(), DynError> {
    let begin = exchange(port, &format!("BeginAuthentication{name}{counter}"), &request(0x06, 0x00, &[role]))?;
    expect_status(&begin, StatusCode::Success)?;
    let challenge_id: [u8; 4] = begin.payload.as_slice()[0..4].try_into().unwrap_or([0; 4]);
    let mut payload = Vec::from(challenge_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.push(u8::try_from(proof.len())?);
    payload.extend_from_slice(proof);
    let complete = exchange(
        port,
        &format!("CompleteAuthentication{name}{counter}"),
        &request(0x07, 0x02, &payload),
    )?;
    expect_status(&complete, StatusCode::AuthorizationError)?;
    settle_after_flash_mutation();
    Ok(())
}

fn begin_provisioning(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
) -> Result<[u8; 4], DynError> {
    let response = exchange(
        port,
        "BeginProvisioning",
        &request(0x80, 0x02, &authorized_payload(session_id, counter, b"lab")),
    )?;
    expect_status(&response, StatusCode::Success)?;
    Ok(response.payload.as_slice()[1..5].try_into().unwrap_or([0; 4]))
}

fn finalize_provisioning(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
    transition_id: [u8; 4],
) -> Result<(), DynError> {
    let inner = [
        transition_id[0],
        transition_id[1],
        transition_id[2],
        transition_id[3],
        finalize_marker(),
    ];
    let response = exchange(
        port,
        "FinalizeProvisioning",
        &request(0x81, 0x02, &authorized_payload(session_id, counter, &inner)),
    )?;
    expect_status(&response, StatusCode::Success)?;
    settle_after_flash_mutation();
    Ok(())
}

fn lock_device(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
) -> Result<(), DynError> {
    let response = exchange(
        port,
        "LockDevice",
        &request(0x82, 0x02, &authorized_payload(session_id, counter, &[0x42])),
    )?;
    expect_status(&response, StatusCode::Success)?;
    settle_after_flash_mutation();
    Ok(())
}

fn unlock_device(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
) -> Result<(), DynError> {
    let response = exchange(
        port,
        "UnlockDevice",
        &request(0x83, 0x02, &authorized_payload(session_id, counter, &[unlock_marker()])),
    )?;
    expect_status(&response, StatusCode::Success)?;
    settle_after_flash_mutation();
    Ok(())
}

fn put_persistent_key(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
    key_id: u8,
    material: &[u8],
) -> Result<(), DynError> {
    let mut inner = vec![key_id, 0x01, 0x01, 0x01, 0x01, u8::try_from(material.len())?];
    inner.extend_from_slice(material);
    let response = exchange(
        port,
        "PutPersistentKey",
        &request(0x89, 0x02, &authorized_payload(session_id, counter, &inner)),
    )?;
    expect_status(&response, StatusCode::Success)?;
    settle_after_flash_mutation();
    Ok(())
}

fn list_persistent_keys(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
) -> Result<(), DynError> {
    let response = exchange(
        port,
        "ListPersistentKeys",
        &request(0x8a, 0x00, &authorized_payload(session_id, counter, &[])),
    )?;
    expect_status(&response, StatusCode::Success)
}

fn replay_list_denied(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
) -> Result<(), DynError> {
    let response = exchange(
        port,
        "ReplayListPersistentKeys",
        &request(0x8a, 0x00, &authorized_payload(session_id, counter, &[])),
    )?;
    expect_status(&response, StatusCode::ReplayError)
}

fn invalidate_session(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
) -> Result<(), DynError> {
    let response = exchange(
        port,
        "InvalidateSession",
        &request(0x09, 0x02, &authorized_payload(session_id, counter, &[])),
    )?;
    expect_status(&response, StatusCode::Success)
}

fn expect_session_inactive(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(port, "GetSessionStatus", &request(0x08, 0x00, &[]))?;
    expect_status(&response, StatusCode::Success)?;
    if response.payload.len() != 6 || response.payload[0] != 0x00 {
        return Err(format!("unexpected session status payload: {}", hex(response.payload.as_slice())).into());
    }
    Ok(())
}

fn developer_reboot(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(port, "DeveloperReboot", &request(0x8f, 0x02, b"RST"))?;
    expect_status(&response, StatusCode::Success)
}

fn probe_lifecycle_status(
    port: &mut dyn serialport::SerialPort,
    expected: &[u8],
) -> Result<(), DynError> {
    let response = exchange(port, "GetLifecycleStatus", &request(0x04, 0x00, &[]))?;
    expect_payload(&response, StatusCode::Success, expected)
}

fn authorized_payload(session_id: [u8; 4], counter: u32, inner: &[u8]) -> Vec<u8> {
    let mut payload = Vec::from(session_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.extend_from_slice(inner);
    payload
}

fn request(code: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let frame = ProtocolFrame::new(MessageKind::Request, code, flags, payload).unwrap_or_default();
    encode_frame(&frame).unwrap_or_default().into_iter().collect()
}

fn exchange(
    port: &mut dyn serialport::SerialPort,
    name: &str,
    request: &[u8],
) -> Result<ProtocolFrame, DynError> {
    println!("\n{name}");
    println!("tx: {}", hex(request));
    port.clear(serialport::ClearBuffer::Input)?;
    port.write_all(request)?;
    port.flush()?;

    let response = read_response(port)?;
    let encoded = encode_frame(&response).unwrap_or_default();
    println!("rx: {}", hex(encoded.as_slice()));
    println!("status: {:02x}, payload: {}", response.code, hex(response.payload.as_slice()));
    Ok(response)
}

fn read_response(port: &mut dyn serialport::SerialPort) -> Result<ProtocolFrame, DynError> {
    let mut buffer = Vec::<u8>::new();
    for _ in 0..READ_RETRY_ATTEMPTS {
        let mut chunk = [0u8; 64];
        match port.read(&mut chunk) {
            Ok(count) if count > 0 => {
                buffer.extend_from_slice(&chunk[..count]);
                if let Some(frame) = find_frame_in_buffer(&buffer) {
                    return Ok(frame);
                }
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => return Err(Box::new(err)),
        }
        thread::sleep(Duration::from_millis(READ_RETRY_DELAY_MS));
    }
    Err("timed out waiting for response".into())
}

fn find_frame_in_buffer(buffer: &[u8]) -> Option<ProtocolFrame> {
    for start in 0..buffer.len() {
        if let Ok(frame) = protocol::protocol::decode_frame(&buffer[start..]) {
            return Some(frame);
        }
    }
    None
}

fn expect_status(frame: &ProtocolFrame, expected: StatusCode) -> Result<(), DynError> {
    if frame.code != expected.as_u8() {
        return Err(format!(
            "unexpected status: expected {:02x}, got {:02x}",
            expected.as_u8(),
            frame.code
        )
        .into());
    }
    Ok(())
}

fn expect_payload(
    frame: &ProtocolFrame,
    expected_status: StatusCode,
    expected_payload: &[u8],
) -> Result<(), DynError> {
    expect_status(frame, expected_status)?;
    if frame.payload.as_slice() != expected_payload {
        return Err(format!(
            "unexpected payload: expected {}, got {}",
            hex(expected_payload),
            hex(frame.payload.as_slice())
        )
        .into());
    }
    Ok(())
}

fn settle_after_flash_mutation() {
    thread::sleep(Duration::from_millis(FLASH_SETTLE_MS));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
