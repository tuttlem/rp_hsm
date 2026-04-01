use heapless::Vec;

use super::codec::{
    DecodeError, StatusCode, clear_bytes, decode_frame, decode_transition_request,
    encode_developer_reset_payload, encode_device_status_payload,
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
    DeviceState, ProvisioningRecord, SessionState, SessionTracker, developer_mode_session,
    developer_reset_marker, enforce_replay_policy, ensure_command_allowed, expect_marker_bytes,
    expect_single_marker, finalize_marker, fingerprint_frame, reactivate_marker,
    recovery_marker, unlock_marker, zeroize_marker,
};

pub struct ProtocolEngine {
    record: ProvisioningRecord,
    session_state: SessionState,
    session_tracker: SessionTracker,
    developer_mode: bool,
}

impl ProtocolEngine {
    #[must_use]
    pub fn new(device_state: DeviceState, session_state: SessionState) -> Self {
        Self {
            record: ProvisioningRecord::new(device_state),
            session_state,
            session_tracker: SessionTracker {
                last_request_fingerprint: None,
            },
            developer_mode: false,
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
    }

    #[must_use]
    pub fn record(&self) -> &ProvisioningRecord {
        &self.record
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
        status_response(StatusCode::Success, &payload)
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
