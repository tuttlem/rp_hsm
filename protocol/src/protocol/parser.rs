use heapless::Vec;

use super::codec::{
    DecodeError, StatusCode, clear_bytes, decode_frame, decode_key_id_request,
    decode_key_marker_request, decode_put_persistent_key_request, decode_transition_request,
    encode_developer_reset_payload, encode_device_status_payload,
    encode_key_destroy_payload, encode_key_list_payload, encode_key_metadata_payload,
    encode_key_record_result_payload, encode_key_store_status_payload,
    encode_lifecycle_status_payload, encode_lock_result_payload,
    encode_recovery_result_payload, encode_state_revision_payload,
    encode_transition_result_payload, encode_zeroize_payload, protocol_version_response,
    status_response,
};
use super::command::{CommandId, get_visible_catalog, lookup_command};
use super::frame::{
    FLAG_INCLUDE_RESTRICTED, FLAG_REPLAY_SENSITIVE, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
};
use super::state::{
    DeviceState, PersistentKeyStore, ProvisioningRecord, ProvisioningSnapshot, SessionState,
    SessionTracker, developer_mode_session, developer_reset_marker, enforce_replay_policy,
    ensure_command_allowed, expect_marker_bytes, expect_single_marker, finalize_marker,
    fingerprint_frame, reactivate_marker, recovery_marker, revoke_marker, unlock_marker,
    zeroize_marker,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeveloperStoreFaultAction {
    CorruptPersistedStore = 0x01,
    RollbackPersistedStore = 0x02,
}

impl DeveloperStoreFaultAction {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::CorruptPersistedStore),
            0x02 => Some(Self::RollbackPersistedStore),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirmwareAction {
    DeveloperStoreFault(DeveloperStoreFaultAction),
    DeveloperReboot,
}

pub struct ProtocolEngine {
    record: ProvisioningRecord,
    key_store: PersistentKeyStore,
    session_state: SessionState,
    session_tracker: SessionTracker,
    developer_mode: bool,
    pending_firmware_action: Option<FirmwareAction>,
}

impl ProtocolEngine {
    #[must_use]
    pub fn new(device_state: DeviceState, session_state: SessionState) -> Self {
        let record = ProvisioningRecord::new(device_state);
        Self {
            key_store: PersistentKeyStore::new(record.revision_counter()),
            record,
            session_state,
            session_tracker: SessionTracker {
                last_request_fingerprint: None,
            },
            developer_mode: false,
            pending_firmware_action: None,
        }
    }

    #[must_use]
    pub fn new_developer_mode() -> Self {
        let mut engine = Self::new(DeviceState::Factory, developer_mode_session());
        engine.developer_mode = true;
        engine
    }

    pub fn set_device_state(&mut self, device_state: DeviceState) {
        self.record = ProvisioningRecord::new(device_state);
        self.key_store = PersistentKeyStore::new(self.record.revision_counter());
        self.pending_firmware_action = None;
    }

    pub fn set_session_state(&mut self, session_state: SessionState) {
        self.session_state = session_state;
    }

    pub fn set_developer_mode(&mut self, developer_mode: bool) {
        self.developer_mode = developer_mode;
        if developer_mode && self.session_state == SessionState::Unauthenticated {
            self.session_state = developer_mode_session();
        }
    }

    pub fn reconcile_boot(&mut self) {
        self.record.reconcile_after_boot();
        self.key_store
            .sync_device_revision(self.record.revision_counter());
        self.key_store.reconcile_after_boot();
    }

    #[must_use]
    pub fn record(&self) -> &ProvisioningRecord {
        &self.record
    }

    #[must_use]
    pub fn provisioning_snapshot(&self) -> ProvisioningSnapshot {
        self.record.snapshot()
    }

    #[must_use]
    pub fn key_store(&self) -> &PersistentKeyStore {
        &self.key_store
    }

    pub fn restore_provisioning_snapshot(&mut self, snapshot: ProvisioningSnapshot) {
        self.record.restore_snapshot(snapshot);
    }

    pub fn restore_key_store(
        &mut self,
        snapshot: super::state::KeyStoreSnapshot,
    ) {
        self.key_store.restore_snapshot(snapshot);
    }

    #[must_use]
    pub fn take_firmware_action(&mut self) -> Option<FirmwareAction> {
        self.pending_firmware_action.take()
    }

    pub fn handle_bytes(&mut self, bytes: &[u8]) -> ProtocolFrame {
        match decode_frame(bytes) {
            Ok(mut frame) => {
                let response = self.handle_frame(&mut frame);
                frame.clear();
                response
            }
            Err(err) => Self::decode_error_response(err),
        }
    }

    fn handle_frame(&mut self, frame: &mut ProtocolFrame) -> ProtocolFrame {
        self.key_store
            .sync_device_revision(self.record.revision_counter());
        if frame.kind != MessageKind::Request {
            return status_response(StatusCode::FormatError, &[]);
        }

        if frame.version != PROTOCOL_VERSION {
            return status_response(StatusCode::VersionError, &[]);
        }

        let Some(command) = lookup_command(frame.code) else {
            return status_response(StatusCode::CommandError, &[]);
        };

        if frame.payload_len() < command.min_payload_len || frame.payload_len() > command.max_payload_len {
            return status_response(StatusCode::ValidationError, &[]);
        }

        if let Err(status) = ensure_command_allowed(
            command,
            self.record.current_state(),
            self.session_state,
            self.developer_mode,
        ) {
            return status_response(status, &[]);
        }

        let fingerprint = fingerprint_frame(frame.code, &frame.payload);
        if frame.flags & FLAG_REPLAY_SENSITIVE != 0
            && let Err(status) =
                enforce_replay_policy(command, &mut self.session_tracker, fingerprint)
        {
            return status_response(status, &[]);
        }

        self.dispatch(frame)
    }

    fn dispatch(&mut self, frame: &mut ProtocolFrame) -> ProtocolFrame {
        match CommandId::from_byte(frame.code) {
            Some(CommandId::GetProtocolVersion) => protocol_version_response(),
            Some(CommandId::GetDeviceStatus) => self.handle_get_device_status(frame),
            Some(CommandId::GetCommandCatalog) => self.handle_get_command_catalog(frame),
            Some(CommandId::GetLifecycleStatus) => self.handle_get_lifecycle_status(),
            Some(CommandId::GetKeyStoreStatus) => self.handle_get_key_store_status(),
            Some(CommandId::BeginProvisioning) => self.handle_begin_provisioning(frame),
            Some(CommandId::FinalizeProvisioning) => self.handle_finalize_provisioning(frame),
            Some(CommandId::LockDevice) => self.handle_lock_device(frame),
            Some(CommandId::UnlockDevice) => self.handle_unlock_device(frame),
            Some(CommandId::EnterRecovery) => self.handle_enter_recovery(frame),
            Some(CommandId::RecoverToProvisioned) => self.handle_recover_to_provisioned(frame),
            Some(CommandId::ReactivateRecoveredProvisioning) => {
                self.handle_reactivate_recovered_provisioning(frame)
            }
            Some(CommandId::ExecuteZeroize) => self.handle_execute_zeroize(frame),
            Some(CommandId::DeveloperResetLifecycle) => self.handle_developer_reset(frame),
            Some(CommandId::PutPersistentKey) => self.handle_put_persistent_key(frame),
            Some(CommandId::ListPersistentKeys) => self.handle_list_persistent_keys(),
            Some(CommandId::GetKeyMetadata) => self.handle_get_key_metadata(frame),
            Some(CommandId::RevokePersistentKey) => self.handle_revoke_persistent_key(frame),
            Some(CommandId::DestroyPersistentKey) => self.handle_destroy_persistent_key(frame),
            Some(CommandId::DeveloperStoreFault) => self.handle_developer_store_fault(frame),
            Some(CommandId::DeveloperReboot) => self.handle_developer_reboot(frame),
            None => status_response(StatusCode::CommandError, &[]),
        }
    }

    fn handle_get_device_status(&self, frame: &ProtocolFrame) -> ProtocolFrame {
        if frame.payload.as_slice() != [0x00] {
            return status_response(StatusCode::ValidationError, &[]);
        }

        let payload =
            encode_device_status_payload(self.record.current_state(), self.session_state);
        status_response(StatusCode::Success, &payload)
    }

    fn handle_get_command_catalog(&self, frame: &ProtocolFrame) -> ProtocolFrame {
        let include_restricted = match frame.payload.as_slice() {
            [0x00] => false,
            [0x01] => true,
            _ => return status_response(StatusCode::ValidationError, &[]),
        };

        let include_restricted = include_restricted && (frame.flags & FLAG_INCLUDE_RESTRICTED != 0);
        let visible = get_visible_catalog(self.session_state, include_restricted, self.developer_mode);
        let mut payload = Vec::<u8, 48>::new();
        let Ok(visible_count) = u8::try_from(visible.len()) else {
            return status_response(StatusCode::InternalError, &[]);
        };
        let _ = payload.push(visible_count);
        for command in visible {
            let _ = payload.push(command.id as u8);
        }
        status_response(StatusCode::Success, &payload)
    }

    fn handle_get_lifecycle_status(&self) -> ProtocolFrame {
        let payload = encode_lifecycle_status_payload(self.record.status());
        status_response(StatusCode::Success, &payload)
    }

    fn handle_get_key_store_status(&self) -> ProtocolFrame {
        let payload = encode_key_store_status_payload(self.key_store.status());
        status_response(StatusCode::Success, &payload)
    }

    fn handle_begin_provisioning(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        match self.record.begin_provisioning(frame.payload.as_slice(), frame.code) {
            Ok(result) => {
                let payload = encode_transition_result_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_finalize_provisioning(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let transition_id = match decode_transition_request(frame.payload.as_slice(), finalize_marker()) {
            Ok(transition_id) => transition_id,
            Err(status) => return status_response(status, &[]),
        };

        match self.record.finalize_provisioning(transition_id) {
            Ok(result) => {
                let payload = encode_state_revision_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_lock_device(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        match self.record.lock_device(frame.payload[0]) {
            Ok(result) => {
                let payload = encode_lock_result_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_unlock_device(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        if let Err(status) = expect_single_marker(frame.payload.as_slice(), unlock_marker()) {
            return status_response(status, &[]);
        }

        match self.record.unlock_device() {
            Ok(result) => {
                let payload = encode_state_revision_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_enter_recovery(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        if let Err(status) = expect_single_marker(frame.payload.as_slice(), recovery_marker()) {
            return status_response(status, &[]);
        }

        match self.record.enter_recovery() {
            Ok(result) => {
                let payload = encode_recovery_result_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_recover_to_provisioned(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        if let Err(status) = expect_single_marker(frame.payload.as_slice(), recovery_marker()) {
            return status_response(status, &[]);
        }

        match self.record.recover_to_provisioned() {
            Ok(result) => {
                let payload = encode_transition_result_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_reactivate_recovered_provisioning(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let transition_id =
            match decode_transition_request(frame.payload.as_slice(), reactivate_marker()) {
                Ok(transition_id) => transition_id,
                Err(status) => return status_response(status, &[]),
            };

        match self.record.reactivate_recovered_provisioning(transition_id) {
            Ok(result) => {
                let payload = encode_state_revision_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_execute_zeroize(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        if let Err(status) = expect_marker_bytes(frame.payload.as_slice(), &zeroize_marker()) {
            return status_response(status, &[]);
        }

        match self.record.execute_zeroize() {
            Ok(result) => {
                self.key_store = PersistentKeyStore::new(self.record.revision_counter());
                let payload = encode_zeroize_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_developer_reset(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        if let Err(status) = expect_marker_bytes(frame.payload.as_slice(), &developer_reset_marker())
        {
            return status_response(status, &[]);
        }

        let payload = encode_developer_reset_payload(self.record.developer_reset());
        self.key_store = PersistentKeyStore::new(self.record.revision_counter());
        status_response(StatusCode::Success, &payload)
    }

    fn handle_put_persistent_key(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let request = match decode_put_persistent_key_request(frame.payload.as_slice()) {
            Ok(request) => request,
            Err(status) => return status_response(status, &[]),
        };

        match self.key_store.put_persistent_key(&request) {
            Ok(result) => {
                let payload = encode_key_record_result_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_list_persistent_keys(&self) -> ProtocolFrame {
        match self.key_store.list_keys() {
            Ok(entries) => {
                let Some(payload) = encode_key_list_payload(entries.as_slice()) else {
                    return status_response(StatusCode::InternalError, &[]);
                };
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_get_key_metadata(&self, frame: &ProtocolFrame) -> ProtocolFrame {
        let key_id = match decode_key_id_request(frame.payload.as_slice()) {
            Ok(key_id) => key_id,
            Err(status) => return status_response(status, &[]),
        };

        match self.key_store.get_key_metadata(key_id) {
            Ok(view) => {
                let payload = encode_key_metadata_payload(view);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_revoke_persistent_key(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let key_id = match decode_key_marker_request(frame.payload.as_slice(), &[revoke_marker()]) {
            Ok(key_id) => key_id,
            Err(status) => return status_response(status, &[]),
        };

        match self.key_store.revoke_key(key_id) {
            Ok(result) => {
                let payload = encode_key_record_result_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_destroy_persistent_key(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let key_id =
            match decode_key_marker_request(frame.payload.as_slice(), &zeroize_marker()) {
                Ok(key_id) => key_id,
                Err(status) => return status_response(status, &[]),
            };

        match self.key_store.destroy_key(key_id) {
            Ok(result) => {
                let payload = encode_key_destroy_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_developer_store_fault(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let Some(action) = frame
            .payload
            .first()
            .and_then(|byte| DeveloperStoreFaultAction::from_byte(*byte))
        else {
            return status_response(StatusCode::ValidationError, &[]);
        };

        self.pending_firmware_action = Some(FirmwareAction::DeveloperStoreFault(action));
        status_response(StatusCode::Success, &[action as u8])
    }

    fn handle_developer_reboot(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        if let Err(status) = expect_marker_bytes(frame.payload.as_slice(), b"RST") {
            return status_response(status, &[]);
        }

        self.pending_firmware_action = Some(FirmwareAction::DeveloperReboot);
        status_response(StatusCode::Success, &[])
    }

    fn decode_error_response(err: DecodeError) -> ProtocolFrame {
        match err {
            DecodeError::Truncated
            | DecodeError::InvalidKind
            | DecodeError::InvalidFlags
            | DecodeError::LengthMismatch
            | DecodeError::OversizedPayload => status_response(StatusCode::FormatError, &[]),
        }
    }
}

pub fn clear_transient_buffer(buffer: &mut [u8]) {
    clear_bytes(buffer);
}
