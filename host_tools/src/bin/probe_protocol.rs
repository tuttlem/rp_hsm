use std::env;
use std::thread;
use std::time::Duration;

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use protocol::protocol::{
    FLAG_INCLUDE_RESTRICTED, KeyAlgorithm, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
    StatusCode, USAGE_WRAP_IMPORT, developer_reset_marker, ed25519_public_key_from_seed,
    encode_frame, finalize_marker, unlock_marker,
};

const DEFAULT_BAUD: u32 = 115_200;
const DEFAULT_TIMEOUT_MS: u64 = 1_000;
const FLASH_SETTLE_MS: u64 = 200;
const REBOOT_SETTLE_MS: u64 = 1_500;
const RECONNECT_ATTEMPTS: usize = 30;
const READ_RETRY_ATTEMPTS: usize = 20;
const READ_RETRY_DELAY_MS: u64 = 150;
const ED25519_SEED: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
const WRAP_KEY: [u8; 32] = *b"wrap-key-material-for-hsm-test!!";

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
    probe_crypto_capabilities(&mut *port)?;

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
    put_persistent_key(
        &mut *port,
        key_manager,
        2,
        0x01,
        0x01,
        &ED25519_SEED,
    )?;
    sign_and_verify(&mut *port, key_manager, 3, 4, 0x01, b"sign me")?;
    generate_random(&mut *port, key_manager, 5, 64)?;
    put_persistent_key(
        &mut *port,
        key_manager,
        6,
        0x07,
        KeyAlgorithm::Aes256 as u8,
        &WRAP_KEY,
    )?;
    import_wrapped_key(&mut *port, key_manager, 7, 0x07, &ED25519_SEED)?;
    let key_manager = authenticate(&mut *port, "KeyManagerReadback", 0x06, b"KEYMG")?;
    list_persistent_keys(&mut *port, key_manager, 2)?;
    replay_list_denied(&mut *port, key_manager, 2)?;
    invalidate_session(&mut *port, key_manager, 3)?;
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
        "All developer-mode authentication, session, and crypto probes passed on {}",
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
        &[0x0a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b],
    )?;
    let restricted = exchange(
        port,
        "GetRestrictedCatalog",
        &request(0x03, FLAG_INCLUDE_RESTRICTED, &[0x01]),
    )?;
    expect_payload(
        &restricted,
        StatusCode::Success,
        &[0x0d, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x88, 0x8e, 0x8f],
    )
}

fn probe_crypto_capabilities(port: &mut dyn serialport::SerialPort) -> Result<(), DynError> {
    let response = exchange(port, "GetCryptoCapabilities", &request(0x0a, 0x00, &[]))?;
    expect_payload(
        &response,
        StatusCode::Success,
        &[0x01, 0x0f, 0x01, 0x03, 0x80, 0x00, 0x40, 0x00, 0x40, 0x01],
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
    algorithm: u8,
    material: &[u8],
) -> Result<(), DynError> {
    let mut inner = vec![key_id, algorithm, 0x01, if algorithm == 0x03 { USAGE_WRAP_IMPORT } else { 0x01 }, 0x01, u8::try_from(material.len())?];
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

fn sign_and_verify(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    sign_counter: u32,
    verify_counter: u32,
    key_id: u8,
    message: &[u8],
) -> Result<(), DynError> {
    let mut inner = vec![
        key_id,
        KeyAlgorithm::Ed25519 as u8,
        u8::try_from(message.len() & 0xff)?,
        u8::try_from((message.len() >> 8) & 0xff)?,
    ];
    inner.extend_from_slice(message);
    let sign = exchange(
        port,
        "SignDetached",
        &request(0x90, 0x02, &authorized_payload(session_id, sign_counter, &inner)),
    )?;
    expect_status(&sign, StatusCode::Success)?;
    let signature_len = usize::from(u16::from_le_bytes([sign.payload[0], sign.payload[1]]));
    let signature = &sign.payload[2..2 + signature_len];
    let public_key = ed25519_public_key_from_seed(&ED25519_SEED).ok_or("failed to derive public key")?;
    let verify = verify_detached(port, "VerifyDetachedTrue", message, &public_key, signature)?;
    expect_payload(&verify, StatusCode::Success, &[0x01])?;
    let mut bad_signature = signature.to_vec();
    if let Some(byte) = bad_signature.first_mut() {
        *byte ^= 0x55;
    }
    let verify_false =
        verify_detached(port, "VerifyDetachedFalse", message, &public_key, &bad_signature)?;
    expect_payload(&verify_false, StatusCode::Success, &[0x00])?;
    let _ = verify_counter;
    Ok(())
}

fn verify_detached(
    port: &mut dyn serialport::SerialPort,
    name: &str,
    message: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> Result<ProtocolFrame, DynError> {
    let mut payload = vec![
        KeyAlgorithm::Ed25519 as u8,
        u8::try_from(message.len() & 0xff)?,
        u8::try_from((message.len() >> 8) & 0xff)?,
    ];
    payload.extend_from_slice(message);
    payload.push(u8::try_from(public_key.len())?);
    payload.extend_from_slice(public_key);
    payload.extend_from_slice(&u16::try_from(signature.len())?.to_le_bytes());
    payload.extend_from_slice(signature);
    exchange(port, name, &request(0x0b, 0x00, &payload))
}

fn generate_random(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
    requested_len: u8,
) -> Result<(), DynError> {
    let response = exchange(
        port,
        "GenerateRandom",
        &request(0x91, 0x02, &authorized_payload(session_id, counter, &[requested_len])),
    )?;
    expect_status(&response, StatusCode::Success)?;
    if response.payload.first().copied() != Some(requested_len) {
        return Err("random length mismatch".into());
    }
    Ok(())
}

fn import_wrapped_key(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
    wrapping_key_id: u8,
    plaintext: &[u8],
) -> Result<(), DynError> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&WRAP_KEY));
    let nonce_bytes = *b"wrapnonce001";
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(
            GenericArray::from_slice(&nonce_bytes),
            b"rp_hsm.wrap.v1",
            &mut ciphertext,
        )
        .map_err(|_| "failed to wrap import payload")?;
    let mut inner = vec![
        0x01,
        wrapping_key_id,
        KeyAlgorithm::Ed25519 as u8,
        0x01,
        0x01,
    ];
    inner.extend_from_slice(&u16::try_from(ciphertext.len())?.to_le_bytes());
    inner.extend_from_slice(&ciphertext);
    inner.push(28);
    inner.extend_from_slice(&nonce_bytes);
    inner.extend_from_slice(tag.as_slice());
    let response = exchange(
        port,
        "ImportWrappedKey",
        &request(0x92, 0x02, &authorized_payload(session_id, counter, &inner)),
    )?;
    expect_status(&response, StatusCode::Success)
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
