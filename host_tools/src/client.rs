use std::thread;
use std::time::Duration;

use ed25519_dalek::Signer;
use protocol::protocol::{
    HEADER_LEN, MessageKind, PROTOCOL_VERSION, ProtocolFrame, StatusCode,
    decode_frame, developer_reset_marker, encode_frame, finalize_marker, reactivate_marker,
    recovery_marker, revoke_marker, unlock_marker, zeroize_marker,
};
use sha2::{Digest, Sha256};

use crate::cli::output::CliError;

const DEFAULT_TIMEOUT_MS: u64 = 1_000;
const FLASH_SETTLE_MS: u64 = 200;
const READ_RETRY_ATTEMPTS: usize = 20;
const READ_RETRY_DELAY_MS: u64 = 150;
const UPDATE_TRUST_ANCHOR_SEED: [u8; 32] = *b"rp_hsm_update_anchor_seed_v1____";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Bootstrap,
    Administrator,
    Recovery,
    KeyManager,
}

impl Role {
    /// # Errors
    ///
    /// Returns `CliError` when the provided role string is unsupported.
    pub fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "bootstrap" => Ok(Self::Bootstrap),
            "administrator" | "admin" => Ok(Self::Administrator),
            "recovery" => Ok(Self::Recovery),
            "key-manager" | "keymanager" => Ok(Self::KeyManager),
            _ => Err(CliError::usage("invalid role value")),
        }
    }

    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Bootstrap => 0x02,
            Self::Administrator => 0x03,
            Self::Recovery => 0x04,
            Self::KeyManager => 0x06,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    pub port_name: String,
    pub baud: u32,
}

impl ClientConfig {
    #[must_use]
    pub fn new(port_name: String, baud: u32) -> Self {
        Self { port_name, baud }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeInfo {
    pub protocol_version: u8,
    pub device_state: u8,
    pub session_state: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusReport {
    pub device_path: String,
    pub protocol_version: u8,
    pub device_state: u8,
    pub session_state: u8,
    pub lifecycle_status: [u8; 4],
    pub key_store_status: [u8; 5],
    pub session_status: [u8; 6],
    pub crypto_capabilities: Option<[u8; 10]>,
    pub firmware_update_status: Option<[u8; 25]>,
    pub policy_profile: Option<[u8; 9]>,
    pub health_status: Option<[u8; 13]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntryRecord {
    pub sequence_id: u32,
    pub event_class: u8,
    pub event_code: u8,
    pub device_revision: u32,
    pub lifecycle_state: u8,
    pub actor_role: u8,
    pub session_kind: u8,
    pub result_class: u8,
    pub detail: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditPage {
    pub entries: Vec<AuditEntryRecord>,
    pub next_sequence: Option<u32>,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvisionResult {
    pub result_state: u8,
    pub transition_id: u32,
    pub revision_counter: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareVersionInput {
    pub security_epoch: u16,
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareUpdateBegin {
    pub target_slot: u8,
    pub update_session_id: u32,
    pub expected_size: u32,
    pub policy_revision: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareUpdateProgress {
    pub bytes_received: u32,
    pub remaining_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareUpdateActivation {
    pub next_boot_slot: u8,
    pub reboot_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyListRecord {
    pub key_id: u8,
    pub algorithm: u8,
    pub lifecycle_state: u8,
    pub usage_mask: u8,
    pub export_policy: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionContext {
    pub role: Role,
    pub session_id: [u8; 4],
    pub next_counter: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeveloperFaultAction {
    CorruptPersistedStore = 0x01,
    RollbackPersistedStore = 0x02,
    CorruptPersistedAudit = 0x03,
    RollbackPersistedAudit = 0x04,
    AmbiguousFirmwareActivation = 0x05,
    RollbackFirmwareVersion = 0x06,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyProfileUpdate {
    pub dual_control_enabled: bool,
}

impl DeveloperFaultAction {
    /// # Errors
    ///
    /// Returns `CliError` when the provided action name is unsupported.
    pub fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "corrupt-persisted-store" | "corrupt" => Ok(Self::CorruptPersistedStore),
            "rollback-persisted-store" | "rollback" => Ok(Self::RollbackPersistedStore),
            "corrupt-persisted-audit" | "corrupt-audit" => Ok(Self::CorruptPersistedAudit),
            "rollback-persisted-audit" | "rollback-audit" => Ok(Self::RollbackPersistedAudit),
            "ambiguous-firmware-activation" | "ambiguous-update" => {
                Ok(Self::AmbiguousFirmwareActivation)
            }
            "rollback-firmware-version" | "rollback-update" => Ok(Self::RollbackFirmwareVersion),
            _ => Err(CliError::usage("invalid developer store fault action")),
        }
    }
}

impl FirmwareVersionInput {
    /// # Errors
    ///
    /// Returns `CliError` when the version string is not `EPOCH.MAJOR.MINOR.PATCH`.
    pub fn parse(value: &str) -> Result<Self, CliError> {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() != 4 {
            return Err(CliError::usage(
                "version must be EPOCH.MAJOR.MINOR.PATCH",
            ));
        }
        Ok(Self {
            security_epoch: parts[0]
                .parse::<u16>()
                .map_err(|_| CliError::usage("invalid security epoch"))?,
            major: parts[1]
                .parse::<u16>()
                .map_err(|_| CliError::usage("invalid major version"))?,
            minor: parts[2]
                .parse::<u16>()
                .map_err(|_| CliError::usage("invalid minor version"))?,
            patch: parts[3]
                .parse::<u16>()
                .map_err(|_| CliError::usage("invalid patch version"))?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyAlgorithm {
    Ed25519 = 0x01,
    P256 = 0x02,
}

impl VerifyAlgorithm {
    /// # Errors
    ///
    /// Returns `CliError` when the provided algorithm name is unsupported.
    pub fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "ed25519" => Ok(Self::Ed25519),
            "p256" => Ok(Self::P256),
            _ => Err(CliError::usage("invalid verify algorithm")),
        }
    }
}

fn build_authorized_request(
    session_id: [u8; 4],
    counter: u32,
    code: u8,
    inner: &[u8],
) -> ProtocolFrame {
    let mut payload = Vec::new();
    payload.extend_from_slice(&session_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.extend_from_slice(inner);
    ProtocolFrame::new(MessageKind::Request, code, 0x02, &payload).unwrap_or_default()
}

fn encode_manifest_payload(
    version: FirmwareVersionInput,
    image: &[u8],
    target_slot: u8,
) -> Result<Vec<u8>, CliError> {
    let digest = Sha256::digest(image);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&UPDATE_TRUST_ANCHOR_SEED);
    let mut message = Vec::new();
    message.push(1);
    message.extend_from_slice(&version.security_epoch.to_le_bytes());
    message.extend_from_slice(&version.major.to_le_bytes());
    message.extend_from_slice(&version.minor.to_le_bytes());
    message.extend_from_slice(&version.patch.to_le_bytes());
    message.extend_from_slice(
        &u32::try_from(image.len())
            .map_err(|_| CliError::usage("image is too large"))?
            .to_le_bytes(),
    );
    message.extend_from_slice(digest.as_slice());
    message.push(target_slot);
    message.extend_from_slice(&0u16.to_le_bytes());
    let signature = signing_key.sign(&message);

    let mut payload = message;
    payload.push(0x01);
    payload.extend_from_slice(
        &u16::try_from(signature.to_bytes().len())
            .map_err(|_| CliError::usage("signature is too large"))?
            .to_le_bytes(),
    );
    payload.extend_from_slice(&signature.to_bytes());
    Ok(payload)
}

pub struct SerialBackend {
    config: ClientConfig,
}

impl SerialBackend {
    #[must_use]
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// # Errors
    ///
    /// Returns `CliError` when the device cannot be opened or does not return
    /// the expected bounded compatibility responses.
    pub fn probe(&self) -> Result<ProbeInfo, CliError> {
        let mut port = open_port(&self.config)?;
        let version_request =
            ProtocolFrame::new(MessageKind::Request, 0x01, 0x00, &[]).unwrap_or_default();
        let version = exchange_frame(&mut *port, &version_request)?;
        ensure_status(&version, StatusCode::Success)?;
        if version.payload.as_slice() != [PROTOCOL_VERSION] {
            return Err(CliError::invalid_response("unexpected protocol version payload"));
        }

        let status_request =
            ProtocolFrame::new(MessageKind::Request, 0x02, 0x00, &[0x00]).unwrap_or_default();
        let status = exchange_frame(&mut *port, &status_request)?;
        ensure_status(&status, StatusCode::Success)?;
        if status.payload.len() != 2 {
            return Err(CliError::invalid_response("unexpected device status payload"));
        }

        Ok(ProbeInfo {
            protocol_version: version.payload[0],
            device_state: status.payload[0],
            session_state: status.payload[1],
        })
    }

    /// # Errors
    ///
    /// Returns `CliError` when any public status command fails or returns a
    /// malformed payload.
    pub fn status_report(&self) -> Result<StatusReport, CliError> {
        let mut port = open_port(&self.config)?;
        let protocol_request =
            ProtocolFrame::new(MessageKind::Request, 0x01, 0x00, &[]).unwrap_or_default();
        let protocol = exchange_frame(&mut *port, &protocol_request)?;
        ensure_status(&protocol, StatusCode::Success)?;
        let device_request =
            ProtocolFrame::new(MessageKind::Request, 0x02, 0x00, &[0x00]).unwrap_or_default();
        let device = exchange_frame(&mut *port, &device_request)?;
        ensure_status(&device, StatusCode::Success)?;
        let lifecycle_request =
            ProtocolFrame::new(MessageKind::Request, 0x04, 0x00, &[]).unwrap_or_default();
        let lifecycle = exchange_frame(&mut *port, &lifecycle_request)?;
        ensure_status(&lifecycle, StatusCode::Success)?;
        let key_store_request =
            ProtocolFrame::new(MessageKind::Request, 0x05, 0x00, &[]).unwrap_or_default();
        let key_store = exchange_frame(&mut *port, &key_store_request)?;
        ensure_status(&key_store, StatusCode::Success)?;
        let session_request =
            ProtocolFrame::new(MessageKind::Request, 0x08, 0x00, &[]).unwrap_or_default();
        let session = exchange_frame(&mut *port, &session_request)?;
        ensure_status(&session, StatusCode::Success)?;
        let crypto_request =
            ProtocolFrame::new(MessageKind::Request, 0x0a, 0x00, &[]).unwrap_or_default();
        let crypto = exchange_frame(&mut *port, &crypto_request)?;
        let crypto_capabilities = if crypto.code == StatusCode::Success.as_u8() {
            Some(copy_array::<10>(crypto.payload.as_slice())?)
        } else if crypto.code == StatusCode::CommandError.as_u8() {
            None
        } else {
            return Err(CliError::invalid_response(format!(
                "unexpected crypto capabilities status {:02x}",
                crypto.code
            )));
        };
        let update_request = build_authorized_request([0; 4], 1, 0x98, &[]);
        let update = exchange_frame(&mut *port, &update_request)?;
        let firmware_update_status = if update.code == StatusCode::Success.as_u8() {
            Some(copy_array::<25>(update.payload.as_slice())?)
        } else if matches!(
            update.code,
            x if x == StatusCode::CommandError.as_u8()
                || x == StatusCode::AuthorizationError.as_u8()
                || x == StatusCode::StateError.as_u8()
        ) {
            None
        } else {
            return Err(CliError::invalid_response(format!(
                "unexpected firmware update status {:02x}",
                update.code
            )));
        };
        let policy_request =
            ProtocolFrame::new(MessageKind::Request, 0x97, 0x00, &[]).unwrap_or_default();
        let policy = exchange_frame(&mut *port, &policy_request)?;
        let policy_profile = if policy.code == StatusCode::Success.as_u8() {
            Some(copy_array::<9>(policy.payload.as_slice())?)
        } else if policy.code == StatusCode::CommandError.as_u8() {
            None
        } else {
            return Err(CliError::invalid_response(format!(
                "unexpected policy status {:02x}",
                policy.code
            )));
        };
        let health_request =
            ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default();
        let health = exchange_frame(&mut *port, &health_request)?;
        let health_status = if health.code == StatusCode::Success.as_u8() {
            Some(copy_array::<13>(health.payload.as_slice())?)
        } else if health.code == StatusCode::CommandError.as_u8() {
            None
        } else {
            return Err(CliError::invalid_response(format!(
                "unexpected health status {:02x}",
                health.code
            )));
        };

        Ok(StatusReport {
            device_path: self.config.port_name.clone(),
            protocol_version: first_payload_byte(&protocol)?,
            device_state: copy_array::<2>(device.payload.as_slice())?[0],
            session_state: copy_array::<2>(device.payload.as_slice())?[1],
            lifecycle_status: copy_array::<4>(lifecycle.payload.as_slice())?,
            key_store_status: copy_array::<5>(key_store.payload.as_slice())?,
            session_status: copy_array::<6>(session.payload.as_slice())?,
            crypto_capabilities,
            firmware_update_status,
            policy_profile,
            health_status,
        })
    }

    /// # Errors
    ///
    /// Returns `CliError` when audit authentication, retrieval, or page decoding fails.
    pub fn get_audit_page(
        &self,
        role: Role,
        proof: &[u8],
        start_sequence: u32,
        max_events: u8,
    ) -> Result<AuditPage, CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, role, proof)?;
        let inner = [
            start_sequence.to_le_bytes()[0],
            start_sequence.to_le_bytes()[1],
            start_sequence.to_le_bytes()[2],
            start_sequence.to_le_bytes()[3],
            max_events,
        ];
        let response = exchange_authorized(&mut *port, &mut session, 0x0d, 0x02, &inner)?;
        ensure_status(&response, StatusCode::Success)?;
        decode_audit_page(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when bootstrap authentication or either provisioning
    /// transition step fails.
    pub fn provision(&self, proof: &[u8], label: &[u8]) -> Result<ProvisionResult, CliError> {
        if label.is_empty() || label.len() > 16 {
            return Err(CliError::usage("provisioning label must be between 1 and 16 bytes"));
        }
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::Bootstrap, proof)?;

        let begin = exchange_authorized(&mut *port, &mut session, 0x80, 0x02, label)?;
        ensure_status(&begin, StatusCode::Success)?;
        let begin_payload = copy_array::<9>(begin.payload.as_slice())?;
        let transition_id = u32::from_le_bytes([
            begin_payload[1],
            begin_payload[2],
            begin_payload[3],
            begin_payload[4],
        ]);

        let finalize_inner = [
            begin_payload[1],
            begin_payload[2],
            begin_payload[3],
            begin_payload[4],
            finalize_marker(),
        ];
        let finalize =
            exchange_authorized(&mut *port, &mut session, 0x81, 0x02, &finalize_inner)?;
        ensure_status(&finalize, StatusCode::Success)?;
        thread::sleep(Duration::from_millis(200));
        let finalize_payload = copy_array::<5>(finalize.payload.as_slice())?;

        Ok(ProvisionResult {
            result_state: finalize_payload[0],
            transition_id,
            revision_counter: u32::from_le_bytes([
                finalize_payload[1],
                finalize_payload[2],
                finalize_payload[3],
                finalize_payload[4],
            ]),
        })
    }

    /// # Errors
    ///
    /// Returns `CliError` when the authentication exchange fails.
    pub fn authenticate(&self, role: Role, proof: &[u8]) -> Result<SessionContext, CliError> {
        let mut port = open_port(&self.config)?;
        authenticate_on_port(&mut *port, role, proof)
    }

    /// # Errors
    ///
    /// Returns `CliError` when bootstrap authentication or the provisioning
    /// transition sequence fails.
    pub fn provision_bootstrap(&self, proof: &[u8], label: &[u8]) -> Result<[u8; 9], CliError> {
        if label.is_empty() || label.len() > 16 {
            return Err(CliError::usage("provisioning label must be between 1 and 16 bytes"));
        }
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::Bootstrap, proof)?;

        let begin = exchange_authorized(&mut *port, &mut session, 0x80, 0x02, label)?;
        ensure_status(&begin, StatusCode::Success)?;
        let begin_payload = copy_array::<9>(begin.payload.as_slice())?;

        let transition_id = &begin_payload[1..5];
        let finalize_inner = [
            transition_id[0],
            transition_id[1],
            transition_id[2],
            transition_id[3],
            finalize_marker(),
        ];
        let finalize =
            exchange_authorized(&mut *port, &mut session, 0x81, 0x02, &finalize_inner)?;
        ensure_status(&finalize, StatusCode::Success)?;
        thread::sleep(Duration::from_millis(200));
        copy_array::<5>(finalize.payload.as_slice())?;
        Ok(begin_payload)
    }

    /// # Errors
    ///
    /// Returns `CliError` when authentication fails for the requested role.
    pub fn auth_check(&self, role: Role, proof: &[u8]) -> Result<SessionContext, CliError> {
        self.authenticate(role, proof)
    }

    /// # Errors
    ///
    /// Returns `CliError` when the developer reset command is unavailable or
    /// the connected developer-mode device rejects it.
    pub fn developer_reset(&self) -> Result<[u8; 4], CliError> {
        let mut port = open_port(&self.config)?;
        let request =
            ProtocolFrame::new(MessageKind::Request, 0x88, 0x02, &developer_reset_marker())
                .unwrap_or_default();
        let response = exchange_frame(&mut *port, &request)?;
        ensure_status(&response, StatusCode::Success)?;
        thread::sleep(Duration::from_millis(200));
        copy_array::<4>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when the connected firmware rejects the developer
    /// reboot request.
    pub fn developer_reboot(&self) -> Result<(), CliError> {
        let mut port = open_port(&self.config)?;
        let request = ProtocolFrame::new(MessageKind::Request, 0x8f, 0x02, b"RST").unwrap_or_default();
        let response = exchange_frame(&mut *port, &request)?;
        ensure_status(&response, StatusCode::Success)
    }

    /// # Errors
    ///
    /// Returns `CliError` when the connected firmware rejects the developer
    /// store fault injection request.
    pub fn developer_store_fault(&self, action: DeveloperFaultAction) -> Result<(), CliError> {
        let mut port = open_port(&self.config)?;
        let request =
            ProtocolFrame::new(MessageKind::Request, 0x8e, 0x02, &[action as u8]).unwrap_or_default();
        let response = exchange_frame(&mut *port, &request)?;
        ensure_status(&response, StatusCode::Success)
    }

    /// # Errors
    ///
    /// Returns `CliError` when the connected firmware rejects the developer
    /// update fault injection request.
    pub fn developer_update_fault(&self, action: DeveloperFaultAction) -> Result<(), CliError> {
        let mut port = open_port(&self.config)?;
        let request =
            ProtocolFrame::new(MessageKind::Request, 0x9f, 0x02, &[action as u8]).unwrap_or_default();
        let response = exchange_frame(&mut *port, &request)?;
        ensure_status(&response, StatusCode::Success)
    }

    /// # Errors
    ///
    /// Returns `CliError` when the connected firmware rejects the developer
    /// policy request.
    pub fn developer_set_policy(
        &self,
        update: PolicyProfileUpdate,
    ) -> Result<[u8; 9], CliError> {
        let mut port = open_port(&self.config)?;
        let request = ProtocolFrame::new(
            MessageKind::Request,
            0x97,
            0x02,
            &[u8::from(update.dual_control_enabled)],
        )
        .unwrap_or_default();
        let response = exchange_frame(&mut *port, &request)?;
        ensure_status(&response, StatusCode::Success)?;
        settle_after_flash_mutation();
        copy_array::<9>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when authentication or random generation fails.
    pub fn get_random(
        &self,
        role: Role,
        proof: &[u8],
        requested_len: u8,
    ) -> Result<Vec<u8>, CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, role, proof)?;
        let response = exchange_authorized(&mut *port, &mut session, 0x91, 0x02, &[requested_len])?;
        ensure_status(&response, StatusCode::Success)?;
        if response.payload.len() != usize::from(requested_len) + 1 || response.payload[0] != requested_len {
            return Err(CliError::invalid_response("unexpected random payload shape"));
        }
        Ok(response.payload[1..].to_vec())
    }

    /// # Errors
    ///
    /// Returns `CliError` when authorization or update status retrieval fails.
    pub fn get_firmware_update_status(
        &self,
        role: Role,
        proof: &[u8],
    ) -> Result<[u8; 25], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, role, proof)?;
        let response = exchange_authorized(&mut *port, &mut session, 0x98, 0x02, &[])?;
        ensure_status(&response, StatusCode::Success)?;
        copy_array::<25>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when update authorization, transfer, finalize, or activation fails.
    pub fn apply_firmware_update(
        &self,
        proof: &[u8],
        version: FirmwareVersionInput,
        image: &[u8],
    ) -> Result<(FirmwareUpdateBegin, FirmwareUpdateActivation), CliError> {
        if image.is_empty() || image.len() > 1024 {
            return Err(CliError::usage("image must be between 1 and 1024 bytes"));
        }
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::Administrator, proof)?;
        let active_status = self.get_firmware_update_status(Role::Administrator, proof)?;
        let active_slot = active_status[0];
        let target_slot = if active_slot == 0x01 { 0x02 } else { 0x01 };
        let manifest_payload = encode_manifest_payload(version, image, target_slot)?;
        let begin = exchange_authorized(&mut *port, &mut session, 0x99, 0x02, &manifest_payload)?;
        ensure_status(&begin, StatusCode::Success)?;
        let begin_payload = copy_array::<13>(begin.payload.as_slice())?;
        let begin_result = FirmwareUpdateBegin {
            target_slot: begin_payload[0],
            update_session_id: u32::from_le_bytes([
                begin_payload[1],
                begin_payload[2],
                begin_payload[3],
                begin_payload[4],
            ]),
            expected_size: u32::from_le_bytes([
                begin_payload[5],
                begin_payload[6],
                begin_payload[7],
                begin_payload[8],
            ]),
            policy_revision: u32::from_le_bytes([
                begin_payload[9],
                begin_payload[10],
                begin_payload[11],
                begin_payload[12],
            ]),
        };
        for (index, chunk) in image.chunks(128).enumerate() {
            let offset = u32::try_from(index * 128).map_err(|_| CliError::usage("image offset overflow"))?;
            let mut inner = Vec::new();
            inner.extend_from_slice(&begin_result.update_session_id.to_le_bytes());
            inner.extend_from_slice(&offset.to_le_bytes());
            inner.extend_from_slice(
                &u16::try_from(chunk.len())
                    .map_err(|_| CliError::usage("chunk too large"))?
                    .to_le_bytes(),
            );
            inner.extend_from_slice(chunk);
            let response = exchange_authorized(&mut *port, &mut session, 0x9a, 0x02, &inner)?;
            ensure_status(&response, StatusCode::Success)?;
            let _ = copy_array::<8>(response.payload.as_slice())?;
        }
        let mut finalize_inner = Vec::new();
        finalize_inner.extend_from_slice(&begin_result.update_session_id.to_le_bytes());
        finalize_inner.push(finalize_marker());
        let finalize = exchange_authorized(&mut *port, &mut session, 0x9b, 0x02, &finalize_inner)?;
        ensure_status(&finalize, StatusCode::Success)?;
        let _ = copy_array::<10>(finalize.payload.as_slice())?;
        let mut activate_inner = Vec::new();
        activate_inner.extend_from_slice(&begin_result.update_session_id.to_le_bytes());
        activate_inner.push(reactivate_marker());
        let activate = exchange_authorized(&mut *port, &mut session, 0x9c, 0x02, &activate_inner)?;
        ensure_status(&activate, StatusCode::Success)?;
        settle_after_flash_mutation();
        let payload = copy_array::<10>(activate.payload.as_slice())?;
        Ok((
            begin_result,
            FirmwareUpdateActivation {
                next_boot_slot: payload[0],
                reboot_required: payload[9] != 0,
            },
        ))
    }

    /// # Errors
    ///
    /// Returns `CliError` when update abort fails.
    pub fn abort_firmware_update(
        &self,
        proof: &[u8],
        update_session_id: u32,
    ) -> Result<[u8; 2], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::Administrator, proof)?;
        let response = exchange_authorized(
            &mut *port,
            &mut session,
            0x9d,
            0x02,
            &update_session_id.to_le_bytes(),
        )?;
        ensure_status(&response, StatusCode::Success)?;
        copy_array::<2>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when trusted recovery fails.
    pub fn recover_trusted_firmware(&self, proof: &[u8]) -> Result<[u8; 10], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::Recovery, proof)?;
        let response = exchange_authorized(
            &mut *port,
            &mut session,
            0x9e,
            0x02,
            &[recovery_marker()],
        )?;
        ensure_status(&response, StatusCode::Success)?;
        settle_after_flash_mutation();
        copy_array::<10>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when administrator authentication or lock fails.
    pub fn lock_device(&self, proof: &[u8]) -> Result<[u8; 2], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::Administrator, proof)?;
        let response = exchange_authorized(&mut *port, &mut session, 0x82, 0x02, &[0x42])?;
        ensure_status(&response, StatusCode::Success)?;
        settle_after_flash_mutation();
        copy_array::<2>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when administrator authentication or unlock fails.
    pub fn unlock_device(&self, proof: &[u8]) -> Result<[u8; 5], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::Administrator, proof)?;
        let response =
            exchange_authorized(&mut *port, &mut session, 0x83, 0x02, &[unlock_marker()])?;
        ensure_status(&response, StatusCode::Success)?;
        settle_after_flash_mutation();
        copy_array::<5>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when administrator authentication or zeroize fails.
    pub fn execute_zeroize(&self, proof: &[u8]) -> Result<[u8; 5], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::Administrator, proof)?;
        let response =
            exchange_authorized(&mut *port, &mut session, 0x87, 0x02, &zeroize_marker())?;
        ensure_status(&response, StatusCode::Success)?;
        settle_after_flash_mutation();
        copy_array::<5>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when session authentication or invalidation fails.
    pub fn logout(&self, role: Role, proof: &[u8]) -> Result<(), CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, role, proof)?;
        let response = exchange_authorized(&mut *port, &mut session, 0x09, 0x02, &[])?;
        ensure_status(&response, StatusCode::Success)
    }

    /// # Errors
    ///
    /// Returns `CliError` when key-manager authentication or signing fails.
    pub fn sign_detached(&self, key_id: u8, proof: &[u8], message: &[u8]) -> Result<Vec<u8>, CliError> {
        if message.is_empty() || message.len() > 128 {
            return Err(CliError::usage("message must be between 1 and 128 bytes"));
        }
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::KeyManager, proof)?;
        let mut inner = Vec::with_capacity(4 + message.len());
        inner.push(key_id);
        inner.push(0x01);
        inner.extend_from_slice(
            &u16::try_from(message.len())
                .map_err(|_| CliError::usage("message is too large"))?
                .to_le_bytes(),
        );
        inner.extend_from_slice(message);
        let response = exchange_authorized(&mut *port, &mut session, 0x90, 0x02, &inner)?;
        ensure_status(&response, StatusCode::Success)?;
        if response.payload.len() < 2 {
            return Err(CliError::invalid_response("signature response is truncated"));
        }
        let signature_len = usize::from(u16::from_le_bytes([response.payload[0], response.payload[1]]));
        if response.payload.len() != 2 + signature_len {
            return Err(CliError::invalid_response("signature response length is invalid"));
        }
        Ok(response.payload[2..].to_vec())
    }

    /// # Errors
    ///
    /// Returns `CliError` when key-manager authentication or wrapped import
    /// fails.
    pub fn import_wrapped_key(&self, proof: &[u8], envelope: &[u8]) -> Result<[u8; 10], CliError> {
        if envelope.is_empty() || envelope.len() > 73 {
            return Err(CliError::usage("wrapped key envelope must be between 1 and 73 bytes"));
        }
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::KeyManager, proof)?;
        let response = exchange_authorized(&mut *port, &mut session, 0x92, 0x02, envelope)?;
        ensure_status(&response, StatusCode::Success)?;
        settle_after_flash_mutation();
        copy_array::<10>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when detached verification fails structurally.
    pub fn verify_detached(
        &self,
        algorithm: VerifyAlgorithm,
        message: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<bool, CliError> {
        if message.is_empty() || message.len() > 128 {
            return Err(CliError::usage("message must be between 1 and 128 bytes"));
        }
        let mut port = open_port(&self.config)?;
        let mut payload = Vec::new();
        payload.push(algorithm as u8);
        payload.extend_from_slice(
            &u16::try_from(message.len())
                .map_err(|_| CliError::usage("message is too large"))?
                .to_le_bytes(),
        );
        payload.extend_from_slice(message);
        payload.push(
            u8::try_from(public_key.len())
                .map_err(|_| CliError::usage("public key is too large"))?,
        );
        payload.extend_from_slice(public_key);
        payload.extend_from_slice(
            &u16::try_from(signature.len())
                .map_err(|_| CliError::usage("signature is too large"))?
                .to_le_bytes(),
        );
        payload.extend_from_slice(signature);
        let request = ProtocolFrame::new(MessageKind::Request, 0x0b, 0x00, &payload).unwrap_or_default();
        let response = exchange_frame(&mut *port, &request)?;
        ensure_status(&response, StatusCode::Success)?;
        match response.payload.as_slice() {
            [0x00] => Ok(false),
            [0x01] => Ok(true),
            _ => Err(CliError::invalid_response("unexpected verify payload")),
        }
    }

    /// # Errors
    ///
    /// Returns `CliError` when authentication or key-list retrieval fails.
    pub fn list_keys(&self, proof: &[u8]) -> Result<Vec<KeyListRecord>, CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::KeyManager, proof)?;
        let response = exchange_authorized(&mut *port, &mut session, 0x8a, 0x00, &[])?;
        ensure_status(&response, StatusCode::Success)?;
        decode_key_list(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when authentication or metadata retrieval fails.
    pub fn get_key_metadata(&self, key_id: u8, proof: &[u8]) -> Result<[u8; 10], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::KeyManager, proof)?;
        let response = exchange_authorized(&mut *port, &mut session, 0x8b, 0x00, &[key_id])?;
        ensure_status(&response, StatusCode::Success)?;
        copy_array::<10>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when key-manager authentication or revocation fails.
    pub fn revoke_key(&self, key_id: u8, proof: &[u8]) -> Result<[u8; 10], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::KeyManager, proof)?;
        let response =
            exchange_authorized(&mut *port, &mut session, 0x8c, 0x02, &[key_id, revoke_marker()])?;
        ensure_status(&response, StatusCode::Success)?;
        copy_array::<10>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when key-manager authentication or destruction fails.
    pub fn destroy_key(&self, key_id: u8, proof: &[u8]) -> Result<[u8; 4], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::KeyManager, proof)?;
        let mut inner = Vec::new();
        inner.push(key_id);
        inner.extend_from_slice(&zeroize_marker());
        let response = exchange_authorized(&mut *port, &mut session, 0x8d, 0x02, &inner)?;
        ensure_status(&response, StatusCode::Success)?;
        settle_after_flash_mutation();
        copy_array::<4>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when recovery authentication or transition fails.
    pub fn enter_recovery(&self, proof: &[u8]) -> Result<[u8; 2], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::Recovery, proof)?;
        let response =
            exchange_authorized(&mut *port, &mut session, 0x84, 0x02, &[recovery_marker()])?;
        ensure_status(&response, StatusCode::Success)?;
        settle_after_flash_mutation();
        copy_array::<2>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when recovery authentication or transition fails.
    pub fn recover_to_provisioned(&self, proof: &[u8]) -> Result<[u8; 9], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::Recovery, proof)?;
        let response =
            exchange_authorized(&mut *port, &mut session, 0x85, 0x02, &[recovery_marker()])?;
        ensure_status(&response, StatusCode::Success)?;
        settle_after_flash_mutation();
        copy_array::<9>(response.payload.as_slice())
    }

    /// # Errors
    ///
    /// Returns `CliError` when recovery authentication or reactivation fails.
    pub fn reactivate_recovered(&self, proof: &[u8], transition_id: u32) -> Result<[u8; 5], CliError> {
        let mut port = open_port(&self.config)?;
        let mut session = authenticate_on_port(&mut *port, Role::Recovery, proof)?;
        let mut inner = Vec::new();
        inner.extend_from_slice(&transition_id.to_le_bytes());
        inner.push(reactivate_marker());
        let response = exchange_authorized(&mut *port, &mut session, 0x86, 0x02, &inner)?;
        ensure_status(&response, StatusCode::Success)?;
        settle_after_flash_mutation();
        copy_array::<5>(response.payload.as_slice())
    }
}

fn authenticate_on_port(
    port: &mut dyn serialport::SerialPort,
    role: Role,
    proof: &[u8],
) -> Result<SessionContext, CliError> {
    let begin_request =
        ProtocolFrame::new(MessageKind::Request, 0x06, 0x00, &[role.to_wire()]).unwrap_or_default();
    let begin = exchange_frame(port, &begin_request)?;
    ensure_status(&begin, StatusCode::Success)?;
    let challenge_id = copy_array::<4>(&begin.payload.as_slice()[0..4])?;
    let mut payload = Vec::from(challenge_id);
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.push(u8::try_from(proof.len()).map_err(|_| CliError::usage("proof is too large"))?);
    payload.extend_from_slice(proof);
    let complete_request =
        ProtocolFrame::new(MessageKind::Request, 0x07, 0x02, &payload).unwrap_or_default();
    let complete = exchange_frame(port, &complete_request)?;
    ensure_status(&complete, StatusCode::Success)?;
    if complete.payload.len() != 11 {
        return Err(CliError::invalid_response("unexpected authentication session payload"));
    }
    Ok(SessionContext {
        role,
        session_id: copy_array::<4>(&complete.payload.as_slice()[0..4])?,
        next_counter: u32::from_le_bytes([
            complete.payload[7],
            complete.payload[8],
            complete.payload[9],
            complete.payload[10],
        ]),
    })
}

fn exchange_authorized(
    port: &mut dyn serialport::SerialPort,
    session: &mut SessionContext,
    code: u8,
    flags: u8,
    inner: &[u8],
) -> Result<ProtocolFrame, CliError> {
    let counter = session.next_counter;
    session.next_counter = session.next_counter.saturating_add(1);
    let mut payload = Vec::from(session.session_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.extend_from_slice(inner);
    let request = ProtocolFrame::new(MessageKind::Request, code, flags, &payload).unwrap_or_default();
    exchange_frame(port, &request)
}

fn open_port(config: &ClientConfig) -> Result<Box<dyn serialport::SerialPort>, CliError> {
    let mut port = serialport::new(&config.port_name, config.baud)
        .timeout(Duration::from_millis(DEFAULT_TIMEOUT_MS))
        .open()
        .map_err(|err| CliError::transport(format!("failed to open {}: {err}", config.port_name)))?;
    port.write_data_terminal_ready(true)
        .map_err(|err| CliError::transport(format!("failed to set DTR on {}: {err}", config.port_name)))?;
    thread::sleep(Duration::from_millis(200));
    Ok(port)
}

fn exchange_frame(
    port: &mut dyn serialport::SerialPort,
    request: &ProtocolFrame,
) -> Result<ProtocolFrame, CliError> {
    let encoded = encode_frame(request)
        .ok_or_else(|| CliError::failure("failed to encode request frame"))?;
    port.clear(serialport::ClearBuffer::Input)
        .map_err(|err| CliError::transport(format!("failed to clear input buffer: {err}")))?;
    port.write_all(encoded.as_slice())
        .map_err(|err| CliError::transport(format!("failed to write request: {err}")))?;
    port.flush()
        .map_err(|err| CliError::transport(format!("failed to flush request: {err}")))?;
    read_response(port)
}

fn read_response(port: &mut dyn serialport::SerialPort) -> Result<ProtocolFrame, CliError> {
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
            Err(err) => return Err(CliError::transport(format!("failed to read response: {err}"))),
        }
        thread::sleep(Duration::from_millis(READ_RETRY_DELAY_MS));
    }
    Err(CliError::transport("timed out waiting for device response"))
}

fn find_frame_in_buffer(buffer: &[u8]) -> Option<ProtocolFrame> {
    for start in 0..buffer.len() {
        if buffer.len() - start < HEADER_LEN {
            continue;
        }
        if let Ok(frame) = decode_frame(&buffer[start..]) {
            return Some(frame);
        }
    }
    None
}

fn ensure_status(frame: &ProtocolFrame, expected: StatusCode) -> Result<(), CliError> {
    if frame.code == StatusCode::AuthorizationError.as_u8()
        || frame.code == StatusCode::CommandError.as_u8()
        || frame.code == StatusCode::StateError.as_u8()
        || frame.code == StatusCode::InternalError.as_u8()
    {
        return Err(map_policy_error(frame));
    }
    if frame.code != expected.as_u8() {
        return Err(CliError::failure(format!(
            "unexpected device status {:02x}",
            frame.code
        )));
    }
    Ok(())
}

fn map_policy_error(frame: &ProtocolFrame) -> CliError {
    let denial = frame.payload.first().copied();
    let ticket_id = frame
        .payload
        .get(1..5)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes);
    match (frame.code, denial, ticket_id) {
        (code, Some(0x01), _) if code == StatusCode::CommandError.as_u8() => {
            CliError::unsupported("operation is unavailable on the connected firmware")
        }
        (code, Some(0x02), _) if code == StatusCode::StateError.as_u8() => {
            CliError::failure("device state does not permit the requested operation")
        }
        (code, Some(0x03), _) if code == StatusCode::AuthorizationError.as_u8() => {
            CliError::auth("active role or session does not permit the requested operation")
        }
        (code, Some(0x04), _) if code == StatusCode::AuthorizationError.as_u8() => {
            CliError::auth("managed-key policy denied the requested operation")
        }
        (code, Some(0x05), Some(ticket_id))
            if code == StatusCode::AuthorizationError.as_u8() =>
        {
            CliError::auth(format!(
                "additional approval is required before execution (ticket_id={ticket_id})"
            ))
        }
        (code, Some(0x06), Some(ticket_id))
            if code == StatusCode::AuthorizationError.as_u8() =>
        {
            CliError::auth(format!(
                "approval is stale and must be restarted (ticket_id={ticket_id})"
            ))
        }
        (code, Some(0x07), _) if code == StatusCode::InternalError.as_u8() => {
            CliError::failure("device policy state is ambiguous and failed closed")
        }
        (code, _, _) if code == StatusCode::AuthorizationError.as_u8() => {
            CliError::auth("device denied the requested operation")
        }
        (code, _, _) if code == StatusCode::CommandError.as_u8() => {
            CliError::unsupported("operation is unavailable on the connected firmware")
        }
        (code, _, _) if code == StatusCode::StateError.as_u8() => {
            CliError::failure("device state does not permit the requested operation")
        }
        _ => CliError::failure(format!("unexpected device status {:02x}", frame.code)),
    }
}

fn first_payload_byte(frame: &ProtocolFrame) -> Result<u8, CliError> {
    frame
        .payload
        .first()
        .copied()
        .ok_or_else(|| CliError::invalid_response("missing payload byte"))
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CliError> {
    bytes
        .try_into()
        .map_err(|_| CliError::invalid_response("unexpected payload length"))
}

fn decode_key_list(payload: &[u8]) -> Result<Vec<KeyListRecord>, CliError> {
    let Some(&count) = payload.first() else {
        return Err(CliError::invalid_response("missing key list count"));
    };
    let expected_len = 1 + usize::from(count) * 5;
    if payload.len() != expected_len {
        return Err(CliError::invalid_response("unexpected key list length"));
    }
    let mut keys = Vec::new();
    for idx in 0..usize::from(count) {
        let start = 1 + idx * 5;
        keys.push(KeyListRecord {
            key_id: payload[start],
            algorithm: payload[start + 1],
            lifecycle_state: payload[start + 2],
            usage_mask: payload[start + 3],
            export_policy: payload[start + 4],
        });
    }
    Ok(keys)
}

fn decode_audit_page(payload: &[u8]) -> Result<AuditPage, CliError> {
    if payload.len() < 7 {
        return Err(CliError::invalid_response("audit page is truncated"));
    }
    let count = usize::from(payload[0]);
    let next_present = payload[1] != 0;
    let next_sequence = u32::from_le_bytes([payload[2], payload[3], payload[4], payload[5]]);
    let truncated = payload[6] != 0;
    let mut cursor = 7usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if payload.len() < cursor + 15 {
            return Err(CliError::invalid_response("audit entry header is truncated"));
        }
        let sequence_id = u32::from_le_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ]);
        let event_class = payload[cursor + 4];
        let event_code = payload[cursor + 5];
        let device_revision = u32::from_le_bytes([
            payload[cursor + 6],
            payload[cursor + 7],
            payload[cursor + 8],
            payload[cursor + 9],
        ]);
        let lifecycle_state = payload[cursor + 10];
        let actor_role = payload[cursor + 11];
        let session_kind = payload[cursor + 12];
        let result_class = payload[cursor + 13];
        let detail_len = usize::from(payload[cursor + 14]);
        cursor += 15;
        if payload.len() < cursor + detail_len {
            return Err(CliError::invalid_response("audit entry detail is truncated"));
        }
        let detail = payload[cursor..cursor + detail_len].to_vec();
        cursor += detail_len;
        entries.push(AuditEntryRecord {
            sequence_id,
            event_class,
            event_code,
            device_revision,
            lifecycle_state,
            actor_role,
            session_kind,
            result_class,
            detail,
        });
    }
    if cursor != payload.len() {
        return Err(CliError::invalid_response("unexpected trailing bytes in audit page"));
    }
    Ok(AuditPage {
        entries,
        next_sequence: next_present.then_some(next_sequence),
        truncated,
    })
}

fn settle_after_flash_mutation() {
    thread::sleep(Duration::from_millis(FLASH_SETTLE_MS));
}
