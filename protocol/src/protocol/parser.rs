use heapless::Vec;

use super::codec::{
    DecodeError, StatusCode, clear_bytes, decode_frame, protocol_version_response, status_response,
};
use super::command::{CommandId, get_visible_catalog, lookup_command};
use super::frame::{
    FLAG_INCLUDE_RESTRICTED, FLAG_REPLAY_SENSITIVE, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
};
use super::state::{
    DeviceState, SessionState, SessionTracker, enforce_replay_policy, ensure_command_allowed,
    fingerprint_frame,
};

pub struct ProtocolEngine {
    device_state: DeviceState,
    session_state: SessionState,
    session_tracker: SessionTracker,
}

impl ProtocolEngine {
    #[must_use]
    pub const fn new(device_state: DeviceState, session_state: SessionState) -> Self {
        Self {
            device_state,
            session_state,
            session_tracker: SessionTracker {
                last_request_fingerprint: None,
            },
        }
    }

    pub fn set_device_state(&mut self, device_state: DeviceState) {
        self.device_state = device_state;
    }

    pub fn set_session_state(&mut self, session_state: SessionState) {
        self.session_state = session_state;
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

        if let Err(status) = ensure_command_allowed(command, self.device_state, self.session_state) {
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

    fn dispatch(&self, frame: &mut ProtocolFrame) -> ProtocolFrame {
        match CommandId::from_byte(frame.code) {
            Some(CommandId::GetProtocolVersion) => protocol_version_response(),
            Some(CommandId::GetDeviceStatus) => self.handle_get_device_status(frame),
            Some(CommandId::GetCommandCatalog) => self.handle_get_command_catalog(frame),
            Some(CommandId::ProvisionDevice | CommandId::FactoryReset) => {
                status_response(StatusCode::StateError, &[])
            }
            None => status_response(StatusCode::CommandError, &[]),
        }
    }

    fn handle_get_device_status(&self, frame: &ProtocolFrame) -> ProtocolFrame {
        if frame.payload.as_slice() != [0x00] {
            return status_response(StatusCode::ValidationError, &[]);
        }

        status_response(
            StatusCode::Success,
            &[self.device_state as u8, self.session_state as u8],
        )
    }

    fn handle_get_command_catalog(&self, frame: &ProtocolFrame) -> ProtocolFrame {
        let include_restricted = match frame.payload.as_slice() {
            [0x00] => false,
            [0x01] => true,
            _ => return status_response(StatusCode::ValidationError, &[]),
        };

        let include_restricted = include_restricted && (frame.flags & FLAG_INCLUDE_RESTRICTED != 0);
        let visible = get_visible_catalog(self.session_state, include_restricted);
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

    fn decode_error_response(err: DecodeError) -> ProtocolFrame {
        match err {
            DecodeError::Truncated | DecodeError::InvalidKind | DecodeError::InvalidFlags | DecodeError::LengthMismatch => {
                status_response(StatusCode::FormatError, &[])
            }
            DecodeError::OversizedPayload => status_response(StatusCode::FormatError, &[]),
        }
    }
}

pub fn clear_transient_buffer(buffer: &mut [u8]) {
    clear_bytes(buffer);
}
