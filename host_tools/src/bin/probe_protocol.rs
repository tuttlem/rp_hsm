use std::env;
use std::thread;
use std::time::Duration;

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use ed25519_dalek::Signer;
use protocol::protocol::{
    FLAG_INCLUDE_RESTRICTED, KeyAlgorithm, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
    StatusCode, USAGE_WRAP_IMPORT, developer_reset_marker, ed25519_public_key_from_seed,
    encode_frame, finalize_marker, reactivate_marker, unlock_marker, zeroize_marker,
};
use sha2::{Digest, Sha256};

const DEFAULT_BAUD: u32 = 115_200;
const DEFAULT_TIMEOUT_MS: u64 = 1_000;
const FLASH_SETTLE_MS: u64 = 200;
const REBOOT_SETTLE_MS: u64 = 1_500;
const RECONNECT_ATTEMPTS: usize = 30;
const READ_RETRY_ATTEMPTS: usize = 20;
const READ_RETRY_DELAY_MS: u64 = 150;
const ED25519_SEED: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
const WRAP_KEY: [u8; 32] = *b"wrap-key-material-for-hsm-test!!";
const UPDATE_TRUST_ANCHOR_SEED: [u8; 32] = *b"rp_hsm_update_anchor_seed_v1____";
const UPDATE_IMAGE_V1_0_0_1: [u8; 96] = [0x5a; 96];

type DynError = Box<dyn std::error::Error>;

#[derive(Clone, Debug)]
struct ProbeConfig {
    port_name: String,
    baud: u32,
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), DynError> {
    let config = parse_args()?;
    let mut port = open_port(&config)?;

    probe_protocol_version(&mut *port)?;
    port = ensure_factory_baseline(&config, port)?;
    probe_public_catalog(&mut *port)?;
    probe_unauthenticated_denial(&mut *port)?;
    probe_crypto_capabilities(&mut *port)?;
    probe_health_status(&mut *port, &[0x01, 0x01, 0x05])?;

    let bootstrap = authenticate(&mut *port, "Bootstrap", 0x02, b"BOOT")?;
    let transition_id = begin_provisioning(&mut *port, bootstrap, 2)?;
    finalize_provisioning(&mut *port, bootstrap, 3, transition_id)?;
    probe_lifecycle_status(&mut *port, &[0x03, 0x01, 0x00, 0x00])?;
    probe_health_status(&mut *port, &[0x03, 0x01, 0x02])?;

    let admin = authenticate(&mut *port, "Administrator", 0x03, b"ADMIN")?;
    probe_firmware_update_status(
        &mut *port,
        admin,
        2,
        [0x01, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x00],
    )?;
    apply_firmware_update(
        &mut *port,
        admin,
        3,
        FirmwareVersionTuple::new(1, 0, 0, 1),
        &UPDATE_IMAGE_V1_0_0_1,
    )?;
    let admin = authenticate(&mut *port, "AdministratorPostUpdate", 0x03, b"ADMIN")?;
    probe_firmware_update_status(
        &mut *port,
        admin,
        2,
        [0x02, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0x00, 0x01, 0x00, 0x04],
    )?;
    rollback_update_denied(
        &mut *port,
        admin,
        3,
        FirmwareVersionTuple::new(1, 0, 0, 1),
        &UPDATE_IMAGE_V1_0_0_1,
    )?;
    let admin = authenticate(&mut *port, "AdministratorPostUpdateLifecycle", 0x03, b"ADMIN")?;
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
    let admin = authenticate(&mut *port, "AdministratorAudit", 0x03, b"ADMIN")?;
    retrieve_audit_page(&mut *port, admin, 3)?;

    set_dual_control(&mut *port, true)?;
    let key_manager = authenticate(&mut *port, "KeyManagerDestroyOne", 0x06, b"KEYMG")?;
    destroy_key_requires_approval(&mut *port, key_manager, 2, 0x01, 0x05)?;
    set_dual_control(&mut *port, false)?;
    set_dual_control(&mut *port, true)?;
    let key_manager = authenticate(&mut *port, "KeyManagerDestroyStale", 0x06, b"KEYMG")?;
    destroy_key_requires_approval(&mut *port, key_manager, 2, 0x01, 0x06)?;
    let key_manager = authenticate(&mut *port, "KeyManagerDestroyThree", 0x06, b"KEYMG")?;
    destroy_key_requires_approval(&mut *port, key_manager, 2, 0x01, 0x05)?;
    let key_manager = authenticate(&mut *port, "KeyManagerDestroyFour", 0x06, b"KEYMG")?;
    destroy_key_succeeds(&mut *port, key_manager, 2, 0x01)?;
    set_dual_control(&mut *port, false)?;

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
    let admin = authenticate(&mut *port, "AdministratorUpdateFault", 0x03, b"ADMIN")?;
    let _ = admin;
    inject_update_fault(&mut *port, 0x05)?;
    developer_reboot(&mut *port)?;
    drop(port);

    let mut port = reopen_after_reboot(&config)?;
    probe_health_status(&mut *port, &[0x05, 0x01, 0x05])?;
    let recovery_session = authenticate(&mut *port, "RecoveryUpdateStatus", 0x04, b"RECVR")?;
    let recovery_status = exchange(
        &mut *port,
        "GetFirmwareUpdateStatusRecovery",
        &request(0x98, 0x02, &authorized_payload(recovery_session, 2, &[])),
    )?;
    expect_status(&recovery_status, StatusCode::Success)?;
    if recovery_status.payload.len() != 25 || recovery_status.payload[19] != 1 || recovery_status.payload[20] != 0x08 {
        return Err(format!(
            "unexpected recovery update status payload: {}",
            hex(recovery_status.payload.as_slice())
        )
        .into());
    }
    let recovery = authenticate(&mut *port, "RecoveryTrustedFirmware", 0x04, b"RECVR")?;
    recover_trusted_firmware(&mut *port, recovery, 2)?;
    probe_health_status(&mut *port, &[0x03, 0x01, 0x05])?;
    let _port = reset_to_factory(&config, port)?;

    println!("All developer-mode authentication, session, crypto, audit, and update probes passed on {}", config.port_name);
    Ok(())
}

#[derive(Clone, Copy)]
struct FirmwareVersionTuple {
    security_epoch: u16,
    major: u16,
    minor: u16,
    patch: u16,
}

impl FirmwareVersionTuple {
    const fn new(security_epoch: u16, major: u16, minor: u16, patch: u16) -> Self {
        Self {
            security_epoch,
            major,
            minor,
            patch,
        }
    }
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
        &[0x0b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c],
    )?;
    let restricted = exchange(
        port,
        "GetRestrictedCatalog",
        &request(0x03, FLAG_INCLUDE_RESTRICTED, &[0x01]),
    )?;
    expect_payload(
        &restricted,
        StatusCode::Success,
        &[
            0x18, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c, 0x0d, 0x98,
            0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x88, 0x8e, 0x8f, 0x97, 0x9f,
        ],
    )
}

fn probe_firmware_update_status(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
    expected_prefix: [u8; 21],
) -> Result<(), DynError> {
    let response = exchange(
        port,
        "GetFirmwareUpdateStatus",
        &request(0x98, 0x02, &authorized_payload(session_id, counter, &[])),
    )?;
    expect_status(&response, StatusCode::Success)?;
    if response.payload.len() != 25 {
        return Err(format!("unexpected firmware update payload length {}", response.payload.len()).into());
    }
    if response.payload.as_slice()[0..21] != expected_prefix {
        return Err(format!(
            "unexpected firmware update status prefix: expected {}, got {}",
            hex(&expected_prefix),
            hex(&response.payload.as_slice()[0..21])
        )
        .into());
    }
    Ok(())
}

fn apply_firmware_update(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    start_counter: u32,
    version: FirmwareVersionTuple,
    image: &[u8],
) -> Result<(), DynError> {
    let active_status = exchange(
        port,
        "GetFirmwareUpdateStatusBeforeApply",
        &request(0x98, 0x02, &authorized_payload(session_id, start_counter, &[])),
    )?;
    expect_status(&active_status, StatusCode::Success)?;
    let target_slot = if active_status.payload.first() == Some(&0x01) { 0x02 } else { 0x01 };
    let manifest = encode_update_manifest(version, image, target_slot)?;
    let begin = exchange(
        port,
        "BeginFirmwareUpdate",
        &request(0x99, 0x02, &authorized_payload(session_id, start_counter + 1, &manifest)),
    )?;
    expect_status(&begin, StatusCode::Success)?;
    if begin.payload.len() != 13 {
        return Err("unexpected begin update payload shape".into());
    }
    let update_session_id = u32::from_le_bytes([
        begin.payload[1],
        begin.payload[2],
        begin.payload[3],
        begin.payload[4],
    ]);
    let mut bytes_received = 0u32;
    for (index, chunk) in image.chunks(64).enumerate() {
        let offset = u32::try_from(index * 64)?;
        let mut inner = Vec::new();
        inner.extend_from_slice(&update_session_id.to_le_bytes());
        inner.extend_from_slice(&offset.to_le_bytes());
        inner.extend_from_slice(&u16::try_from(chunk.len())?.to_le_bytes());
        inner.extend_from_slice(chunk);
        let response = exchange(
            port,
            &format!("TransferFirmwareChunk{}", index + 1),
            &request(
                0x9a,
                0x02,
                &authorized_payload(session_id, start_counter + 2 + u32::try_from(index)?, &inner),
            ),
        )?;
        expect_status(&response, StatusCode::Success)?;
        bytes_received = bytes_received.saturating_add(u32::try_from(chunk.len())?);
        let expected_remaining = u32::try_from(image.len())?.saturating_sub(bytes_received);
        let expected_progress = [
            bytes_received.to_le_bytes()[0],
            bytes_received.to_le_bytes()[1],
            bytes_received.to_le_bytes()[2],
            bytes_received.to_le_bytes()[3],
            expected_remaining.to_le_bytes()[0],
            expected_remaining.to_le_bytes()[1],
            expected_remaining.to_le_bytes()[2],
            expected_remaining.to_le_bytes()[3],
        ];
        expect_payload(&response, StatusCode::Success, &expected_progress)?;
    }
    let transfer_counter = start_counter + 2 + u32::try_from(image.chunks(64).count())?;
    let mut finalize = Vec::new();
    finalize.extend_from_slice(&update_session_id.to_le_bytes());
    finalize.push(finalize_marker());
    let finalize_response = exchange(
        port,
        "FinalizeFirmwareUpdate",
        &request(0x9b, 0x02, &authorized_payload(session_id, transfer_counter, &finalize)),
    )?;
    expect_status(&finalize_response, StatusCode::Success)?;
    let mut activate = Vec::new();
    activate.extend_from_slice(&update_session_id.to_le_bytes());
    activate.push(reactivate_marker());
    let activate_response = exchange(
        port,
        "ActivateFirmwareUpdate",
        &request(0x9c, 0x02, &authorized_payload(session_id, transfer_counter + 1, &activate)),
    )?;
    expect_status(&activate_response, StatusCode::Success)?;
    settle_after_flash_mutation();
    Ok(())
}

fn rollback_update_denied(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
    version: FirmwareVersionTuple,
    image: &[u8],
) -> Result<(), DynError> {
    let manifest = encode_update_manifest(version, image, 0x01)?;
    let response = exchange(
        port,
        "BeginFirmwareUpdateRollbackDenied",
        &request(0x99, 0x02, &authorized_payload(session_id, counter, &manifest)),
    )?;
    expect_status(&response, StatusCode::AuthorizationError)?;
    if response.payload.as_slice() != [0x04] {
        return Err(format!(
            "unexpected rollback denial payload: {}",
            hex(response.payload.as_slice())
        )
        .into());
    }
    Ok(())
}

fn recover_trusted_firmware(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
) -> Result<(), DynError> {
    let response = exchange(
        port,
        "RecoverTrustedFirmware",
        &request(0x9e, 0x02, &authorized_payload(session_id, counter, &[0xc3])),
    )?;
    expect_status(&response, StatusCode::Success)?;
    settle_after_flash_mutation();
    Ok(())
}

fn inject_update_fault(port: &mut dyn serialport::SerialPort, action: u8) -> Result<(), DynError> {
    let response = exchange(
        port,
        "DeveloperUpdateFault",
        &request(0x9f, 0x02, &[action]),
    )?;
    expect_status(&response, StatusCode::Success)?;
    settle_after_flash_mutation();
    Ok(())
}

fn encode_update_manifest(
    version: FirmwareVersionTuple,
    image: &[u8],
    target_slot: u8,
) -> Result<Vec<u8>, DynError> {
    let digest = Sha256::digest(image);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&UPDATE_TRUST_ANCHOR_SEED);
    let mut message = Vec::new();
    message.push(1);
    message.extend_from_slice(&version.security_epoch.to_le_bytes());
    message.extend_from_slice(&version.major.to_le_bytes());
    message.extend_from_slice(&version.minor.to_le_bytes());
    message.extend_from_slice(&version.patch.to_le_bytes());
    message.extend_from_slice(&u32::try_from(image.len())?.to_le_bytes());
    message.extend_from_slice(digest.as_slice());
    message.push(target_slot);
    message.extend_from_slice(&0u16.to_le_bytes());
    let signature = signing_key.sign(&message).to_bytes();

    let mut payload = message;
    payload.push(0x01);
    payload.extend_from_slice(&u16::try_from(signature.len())?.to_le_bytes());
    payload.extend_from_slice(&signature);
    Ok(payload)
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

fn probe_health_status(
    port: &mut dyn serialport::SerialPort,
    expected_prefix: &[u8],
) -> Result<(), DynError> {
    let response = exchange(port, "GetHealthStatus", &request(0x0c, 0x00, &[]))?;
    expect_status(&response, StatusCode::Success)?;
    if response.payload.len() != 13 {
        return Err(format!("unexpected health payload length {}", response.payload.len()).into());
    }
    if &response.payload.as_slice()[0..expected_prefix.len()] != expected_prefix {
        return Err(format!(
            "unexpected health prefix: expected {}, got {}",
            hex(expected_prefix),
            hex(&response.payload.as_slice()[0..expected_prefix.len()])
        )
        .into());
    }
    Ok(())
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

fn retrieve_audit_page(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
) -> Result<(), DynError> {
    let response = exchange(
        port,
        "GetAuditPage",
        &request(0x0d, 0x02, &authorized_payload(session_id, counter, &[0, 0, 0, 0, 4])),
    )?;
    expect_status(&response, StatusCode::Success)?;
    let payload = response.payload.as_slice();
    if payload.len() < 6 {
        return Err("audit page payload is truncated".into());
    }
    let entry_count = usize::from(payload[0]);
    if entry_count == 0 {
        return Err("audit page returned no entries".into());
    }
    let mut cursor = 6usize;
    let mut previous_sequence = 0u32;
    for _ in 0..entry_count {
        if payload.len() < cursor + 14 {
            return Err("audit entry header is truncated".into());
        }
        let sequence = u32::from_le_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ]);
        if sequence <= previous_sequence {
            return Err("audit sequence ordering is not monotonic".into());
        }
        previous_sequence = sequence;
        let detail_len = usize::from(payload[cursor + 13]);
        cursor += 14;
        if payload.len() < cursor + detail_len {
            return Err("audit entry detail is truncated".into());
        }
        cursor += detail_len;
    }
    if cursor != payload.len() {
        return Err("audit page payload has trailing bytes".into());
    }
    Ok(())
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

fn set_dual_control(
    port: &mut dyn serialport::SerialPort,
    enabled: bool,
) -> Result<(), DynError> {
    let response = exchange(
        port,
        if enabled {
            "DeveloperSetPolicyDualControlOn"
        } else {
            "DeveloperSetPolicyDualControlOff"
        },
        &request(0x97, 0x02, &[u8::from(enabled)]),
    )?;
    expect_status(&response, StatusCode::Success)?;
    if response.payload.len() != 9 {
        return Err("unexpected policy payload shape".into());
    }
    if response.payload[5] != u8::from(enabled) {
        return Err("unexpected dual-control flag state".into());
    }
    settle_after_flash_mutation();
    Ok(())
}

fn destroy_key_requires_approval(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
    key_id: u8,
    denial_class: u8,
) -> Result<(), DynError> {
    let mut inner = vec![key_id];
    inner.extend_from_slice(&zeroize_marker());
    let response = exchange(
        port,
        "DestroyKeyRequiresApproval",
        &request(0x8d, 0x02, &authorized_payload(session_id, counter, &inner)),
    )?;
    expect_status(&response, StatusCode::AuthorizationError)?;
    if response.payload.len() != 5 || response.payload[0] != denial_class {
        return Err(
            format!(
                "unexpected approval denial payload: {}",
                hex(response.payload.as_slice())
            )
            .into(),
        );
    }
    Ok(())
}

fn destroy_key_succeeds(
    port: &mut dyn serialport::SerialPort,
    session_id: [u8; 4],
    counter: u32,
    key_id: u8,
) -> Result<(), DynError> {
    let mut inner = vec![key_id];
    inner.extend_from_slice(&zeroize_marker());
    let response = exchange(
        port,
        "DestroyKeyApproved",
        &request(0x8d, 0x02, &authorized_payload(session_id, counter, &inner)),
    )?;
    expect_status(&response, StatusCode::Success)?;
    settle_after_flash_mutation();
    Ok(())
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
