use std::env;
use std::thread;
use std::time::Duration;

use protocol::protocol::{
    FLAG_INCLUDE_RESTRICTED, MessageKind, PROTOCOL_VERSION, ProtocolFrame, StatusCode,
    developer_reset_marker, encode_frame, finalize_marker, reactivate_marker, recovery_marker,
    unlock_marker, zeroize_marker,
};

const DEFAULT_BAUD: u32 = 115_200;
const DEFAULT_TIMEOUT_MS: u64 = 250;

type DynError = Box<dyn std::error::Error>;

fn main() -> Result<(), DynError> {
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
                return Ok(());
            }
            other => {
                return Err(format!("unknown argument: {other}").into());
            }
        }
    }

    let mut port = serialport::new(&port_name, baud)
        .timeout(Duration::from_millis(DEFAULT_TIMEOUT_MS))
        .open()?;
    port.write_data_terminal_ready(true)?;
    thread::sleep(Duration::from_millis(200));

    probe_protocol_version(&mut *port)?;
    probe_device_status(&mut *port)?;
    probe_public_catalog(&mut *port)?;
    probe_lifecycle_status(&mut *port, &[0x01, 0x00, 0x00, 0x00])?;
    let transition_id = probe_begin_provisioning(&mut *port)?;
    probe_lifecycle_status(&mut *port, &[0x02, 0x01, 0x00, 0x01])?;
    probe_finalize_provisioning(&mut *port, transition_id)?;
    probe_lifecycle_status(&mut *port, &[0x03, 0x01, 0x00, 0x00])?;
    probe_invalid_finalize_in_operational(&mut *port, transition_id)?;
    probe_lock_unlock(&mut *port)?;
    probe_recovery_roundtrip(&mut *port)?;
    probe_zeroize(&mut *port)?;
    probe_lifecycle_status(&mut *port, &[0x06, 0x00, 0x00, 0x00])?;
    probe_developer_reset(&mut *port)?;
    probe_lifecycle_status(&mut *port, &[0x01, 0x00, 0x00, 0x00])?;

    println!("All developer-mode lifecycle probes passed on {port_name}");
    Ok(())
}

fn print_help() {
    println!("Usage: cargo probe -- --port /dev/ttyACM0 [--baud 115200]");
}

fn probe_protocol_version(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(port, "GetProtocolVersion", &request(0x01, 0x00, &[]))?;
    expect_payload(&response, StatusCode::Success, &[PROTOCOL_VERSION])?;
    Ok(())
}

fn probe_device_status(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(port, "GetDeviceStatus", &request(0x02, 0x00, &[0x00]))?;
    expect_payload(&response, StatusCode::Success, &[0x01, 0x05])?;
    Ok(())
}

fn probe_public_catalog(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(port, "GetCommandCatalog", &request(0x03, 0x00, &[0x00]))?;
    expect_payload(&response, StatusCode::Success, &[0x04, 0x01, 0x02, 0x03, 0x04])?;

    let restricted = exchange(
        port,
        "GetRestrictedCatalog",
        &request(0x03, FLAG_INCLUDE_RESTRICTED, &[0x01]),
    )?;
    expect_payload(
        &restricted,
        StatusCode::Success,
        &[0x0d, 0x01, 0x02, 0x03, 0x04, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88],
    )?;
    Ok(())
}

fn probe_lifecycle_status(
    port: &mut dyn serialport::SerialPort,
    expected: &[u8],
) -> Result<(), DynError> {
    let response = exchange(port, "GetLifecycleStatus", &request(0x04, 0x00, &[]))?;
    expect_payload(&response, StatusCode::Success, expected)?;
    Ok(())
}

fn probe_begin_provisioning(port: &mut dyn serialport::SerialPort) -> Result<[u8; 4], DynError> {
    let response = exchange(port, "BeginProvisioning", &request(0x80, 0x02, b"lab"))?;
    expect_status(&response, StatusCode::Success)?;
    if response.payload.len() != 9 || response.payload[0] != 0x02 {
        return Err(format!("unexpected begin payload: {}", hex(response.payload.as_slice())).into());
    }
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
    expect_status(&response, StatusCode::StateError)?;
    Ok(())
}

fn probe_lock_unlock(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let lock = exchange(port, "LockDevice", &request(0x82, 0x02, &[0x42]))?;
    expect_payload(&lock, StatusCode::Success, &[0x04, 0x42])?;
    probe_lifecycle_status(port, &[0x04, 0x01, 0x00, 0x00])?;

    let unlock = exchange(port, "UnlockDevice", &request(0x83, 0x02, &[unlock_marker()]))?;
    expect_status(&unlock, StatusCode::Success)?;
    if unlock.payload.first() != Some(&0x03) {
        return Err(format!("unexpected unlock payload: {}", hex(unlock.payload.as_slice())).into());
    }
    Ok(())
}

fn probe_recovery_roundtrip(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let _ = exchange(port, "LockDeviceForRecovery", &request(0x82, 0x02, &[0x24]))?;
    let recovery =
        exchange(port, "EnterRecovery", &request(0x84, 0x02, &[recovery_marker()]))?;
    expect_payload(&recovery, StatusCode::Success, &[0x05, 0x01])?;

    let recover = exchange(
        port,
        "RecoverToProvisioned",
        &request(0x85, 0x02, &[recovery_marker()]),
    )?;
    expect_status(&recover, StatusCode::Success)?;
    if recover.payload.first() != Some(&0x02) || recover.payload.len() < 5 {
        return Err(format!("unexpected recover payload: {}", hex(recover.payload.as_slice())).into());
    }
    let reactivation_id = [
        recover.payload[1],
        recover.payload[2],
        recover.payload[3],
        recover.payload[4],
    ];
    probe_lifecycle_status(port, &[0x02, 0x01, 0x00, 0x01])?;

    let reactivate = exchange(
        port,
        "ReactivateRecoveredProvisioning",
        &request(
            0x86,
            0x02,
            &[
                reactivation_id[0],
                reactivation_id[1],
                reactivation_id[2],
                reactivation_id[3],
                reactivate_marker(),
            ],
        ),
    )?;
    expect_status(&reactivate, StatusCode::Success)?;
    if reactivate.payload.first() != Some(&0x03) {
        return Err(format!("unexpected reactivate payload: {}", hex(reactivate.payload.as_slice())).into());
    }

    Ok(())
}

fn probe_zeroize(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let marker = zeroize_marker();
    let response = exchange(port, "ExecuteZeroize", &request(0x87, 0x02, &marker))?;
    expect_payload(&response, StatusCode::Success, &[0x06, 0x01, 0x01, 0x01, 0x01])?;
    Ok(())
}

fn probe_developer_reset(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let marker = developer_reset_marker();
    let response = exchange(port, "DeveloperResetLifecycle", &request(0x88, 0x02, &marker))?;
    expect_payload(&response, StatusCode::Success, &[0x01, 0x01, 0x01, 0x01])?;
    Ok(())
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
    port.read_exact(&mut header)?;
    let payload_len = usize::from(u16::from_le_bytes([header[4], header[5]]));
    let mut bytes = header.to_vec();
    if payload_len > 0 {
        let mut payload = vec![0u8; payload_len];
        port.read_exact(&mut payload)?;
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

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
