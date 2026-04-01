use std::env;
use std::thread;
use std::time::Duration;

use protocol::protocol::{
    FLAG_INCLUDE_RESTRICTED, MessageKind, PROTOCOL_VERSION, ProtocolFrame, StatusCode,
    decode_frame, encode_frame,
};

const DEFAULT_BAUD: u32 = 115_200;
const DEFAULT_TIMEOUT_MS: u64 = 250;

type DynError = Box<dyn std::error::Error>;

struct ProbeCase {
    name: &'static str,
    request: Vec<u8>,
    expected: Vec<u8>,
}

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

    let cases = suite()?;
    for case in &cases {
        run_case(&mut *port, case)?;
    }

    println!("All protocol probes passed on {port_name}");
    Ok(())
}

fn print_help() {
    println!("Usage: cargo probe -- --port /dev/ttyACM0 [--baud 115200]");
}

fn suite() -> Result<Vec<ProbeCase>, DynError> {
    Ok(vec![
        ProbeCase {
            name: "GetProtocolVersion",
            request: encode_request(PROTOCOL_VERSION, 0x01, 0x00, &[])?,
            expected: encode_response(StatusCode::Success, &[PROTOCOL_VERSION])?,
        },
        ProbeCase {
            name: "GetDeviceStatus",
            request: encode_request(PROTOCOL_VERSION, 0x02, 0x00, &[0x00])?,
            expected: encode_response(StatusCode::Success, &[0x03, 0x01])?,
        },
        ProbeCase {
            name: "GetCommandCatalog",
            request: encode_request(PROTOCOL_VERSION, 0x03, 0x00, &[0x00])?,
            expected: encode_response(StatusCode::Success, &[0x03, 0x01, 0x02, 0x03])?,
        },
        ProbeCase {
            name: "UnknownCommand",
            request: encode_request(PROTOCOL_VERSION, 0x55, 0x00, &[])?,
            expected: encode_response(StatusCode::CommandError, &[])?,
        },
        ProbeCase {
            name: "ReservedCommand",
            request: encode_request(PROTOCOL_VERSION, 0x80, 0x00, &[])?,
            expected: encode_response(StatusCode::AuthorizationError, &[])?,
        },
        ProbeCase {
            name: "BadVersion",
            request: encode_request(0x09, 0x01, 0x00, &[])?,
            expected: encode_response(StatusCode::VersionError, &[])?,
        },
        ProbeCase {
            name: "Truncated",
            request: vec![PROTOCOL_VERSION, MessageKind::Request as u8, 0x01],
            expected: encode_response(StatusCode::FormatError, &[])?,
        },
        ProbeCase {
            name: "RestrictedCatalogHidden",
            request: encode_request(
                PROTOCOL_VERSION,
                0x03,
                FLAG_INCLUDE_RESTRICTED,
                &[0x01],
            )?,
            expected: encode_response(StatusCode::Success, &[0x03, 0x01, 0x02, 0x03])?,
        },
    ])
}

fn run_case(port: &mut dyn serialport::SerialPort, case: &ProbeCase) -> Result<(), DynError> {
    port.clear(serialport::ClearBuffer::All)?;
    port.write_all(&case.request)?;
    port.flush()?;
    thread::sleep(Duration::from_millis(100));

    let mut response = vec![0u8; case.expected.len()];
    port.read_exact(&mut response)?;

    println!("\n{}", case.name);
    println!("tx: {}", hex(&case.request));
    println!("rx: {}", hex(&response));

    if response != case.expected {
        return Err(format!(
            "{} mismatch: expected {}, got {}",
            case.name,
            hex(&case.expected),
            hex(&response)
        )
        .into());
    }

    let decoded = decode_frame(&response)
        .map_err(|err| format!("{} decode failed: {err:?}", case.name))?;
    println!(
        "status: {:02x}, payload: {}",
        decoded.code,
        hex(decoded.payload.as_slice())
    );
    Ok(())
}

fn encode_request(version: u8, code: u8, flags: u8, payload: &[u8]) -> Result<Vec<u8>, DynError> {
    let Some(mut frame) = ProtocolFrame::new(MessageKind::Request, code, flags, payload) else {
        return Err("failed to create request frame".into());
    };
    frame.version = version;
    let Some(encoded) = encode_frame(&frame) else {
        return Err("failed to encode request frame".into());
    };
    Ok(encoded.into_iter().collect())
}

fn encode_response(status: StatusCode, payload: &[u8]) -> Result<Vec<u8>, DynError> {
    let Some(frame) = ProtocolFrame::new(MessageKind::Response, status.as_u8(), 0, payload) else {
        return Err("failed to create response frame".into());
    };
    let Some(encoded) = encode_frame(&frame) else {
        return Err("failed to encode response frame".into());
    };
    Ok(encoded.into_iter().collect())
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
