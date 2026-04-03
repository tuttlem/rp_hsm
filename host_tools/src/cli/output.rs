use std::fmt;

use crate::client::AuditPage;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    Success = 0,
    Usage = 2,
    NotFound = 3,
    Unsupported = 4,
    Auth = 5,
    Transport = 6,
    InvalidResponse = 7,
    Failure = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Usage,
    NotFound,
    Unsupported,
    DeviceDenied,
    Transport,
    InvalidResponse,
    Failure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportCondition {
    BusyPort,
    MissingPermission,
    MissingDevice,
    ReenumeratingDevice,
    CompetingService,
    TimedOut,
    IncompatibleFirmware,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandOutput {
    Text(String),
    Bytes(Vec<u8>),
}

impl CommandOutput {
    #[must_use]
    pub fn into_stdout(self) -> Vec<u8> {
        match self {
            Self::Text(text) => text.into_bytes(),
            Self::Bytes(bytes) => bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliError {
    pub message: String,
    pub exit_status: ExitStatus,
    pub kind: ErrorKind,
    pub transport_condition: Option<TransportCondition>,
}

impl CliError {
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::Usage,
            kind: ErrorKind::Usage,
            transport_condition: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::NotFound,
            kind: ErrorKind::NotFound,
            transport_condition: None,
        }
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::Unsupported,
            kind: ErrorKind::Unsupported,
            transport_condition: None,
        }
    }

    pub fn auth(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::Auth,
            kind: ErrorKind::DeviceDenied,
            transport_condition: None,
        }
    }

    pub fn transport(message: impl Into<String>) -> Self {
        Self::transport_with_condition(message, TransportCondition::Other)
    }

    pub fn transport_with_condition(
        message: impl Into<String>,
        condition: TransportCondition,
    ) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::Transport,
            kind: ErrorKind::Transport,
            transport_condition: Some(condition),
        }
    }

    pub fn invalid_response(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::InvalidResponse,
            kind: ErrorKind::InvalidResponse,
            transport_condition: None,
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::Failure,
            kind: ErrorKind::Failure,
            transport_condition: None,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for CliError {}

#[must_use]
pub fn lines_output(lines: &[String]) -> CommandOutput {
    let mut text = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if idx > 0 {
            text.push('\n');
        }
        text.push_str(line);
    }
    if !text.is_empty() {
        text.push('\n');
    }
    CommandOutput::Text(text)
}

#[must_use]
pub fn audit_page_lines(device: &str, page: &AuditPage, one_line: bool) -> Vec<String> {
    let mut lines = vec![
        format!("Device: {device}"),
        format!("Entries: {}", page.entries.len()),
        format!(
            "Next sequence: {}",
            page.next_sequence
                .map_or_else(|| "none".to_string(), |value| value.to_string())
        ),
        format!("Truncated: {}", if page.truncated { "yes" } else { "no" }),
    ];
    for entry in &page.entries {
        if one_line {
            lines.push(format!(
                "#{}  {}  {}/{}  actor={}  result={}  detail={}",
                entry.sequence_id,
                audit_session_kind_name(entry.session_kind),
                audit_event_class_name(entry.event_class),
                audit_event_code_name(entry.event_class, entry.event_code),
                audit_role_name(entry.actor_role),
                audit_result_class_name(entry.result_class),
                audit_detail_text(&entry.detail),
            ));
        } else {
            lines.push(String::new());
            lines.push(format!(
                "Sequence {} | {} session",
                entry.sequence_id,
                audit_session_kind_name(entry.session_kind),
            ));
            lines.push(format!(
                "  Event: {} / {}",
                audit_event_class_name(entry.event_class),
                audit_event_code_name(entry.event_class, entry.event_code),
            ));
            lines.push(format!("  Actor: {}", audit_role_name(entry.actor_role)));
            lines.push(format!(
                "  Result: {}",
                audit_result_class_name(entry.result_class)
            ));
            lines.push(format!("  Detail: {}", audit_detail_text(&entry.detail)));
        }
    }
    lines
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut text, "{byte:02x}");
    }
    text
}

fn audit_role_name(value: u8) -> &'static str {
    match value {
        0x00 => "public",
        0x02 => "bootstrap",
        0x03 => "administrator",
        0x04 => "recovery",
        0x05 => "developer",
        0x06 => "key-manager",
        _ => "unknown",
    }
}

fn audit_session_kind_name(value: u8) -> &'static str {
    match value {
        0x00 => "none",
        0x01 => "public",
        0x02 => "bootstrap",
        0x03 => "administrator",
        0x04 => "recovery",
        0x05 => "developer",
        0x06 => "key-manager",
        _ => "unknown",
    }
}

fn audit_event_class_name(value: u8) -> &'static str {
    match value {
        0x01 => "system",
        0x02 => "authentication",
        0x03 => "lifecycle",
        0x04 => "key-store",
        0x05 => "policy",
        0x06 => "crypto",
        0x07 => "audit",
        0x08 => "firmware-update",
        _ => "unknown",
    }
}

fn audit_event_code_name(class: u8, code: u8) -> &'static str {
    match (class, code) {
        (0x01, 0x01) => "developer-reset",
        (0x01, 0x02) => "developer-reboot",
        (0x02, 0x01) => "authentication-begin",
        (0x02, 0x02) => "authentication-complete",
        (0x02, 0x03) => "authentication-denied",
        (0x03, 0x01) => "state-transition",
        (0x03, 0x02) => "recovery-entry",
        (0x03, 0x03) => "zeroize",
        (0x04, 0x01) => "key-created",
        (0x04, 0x02) => "key-listed",
        (0x04, 0x03) => "key-metadata",
        (0x04, 0x04) => "key-revoked",
        (0x04, 0x05) => "key-destroyed",
        (0x05, 0x01) => "policy-updated",
        (0x05, 0x02) => "approval-required",
        (0x05, 0x03) => "approval-stale",
        (0x06, 0x01) => "sign",
        (0x06, 0x02) => "verify",
        (0x06, 0x03) => "random-generated",
        (0x07, 0x01) => "audit-page-read",
        (0x08, 0x01) => "update-begin",
        (0x08, 0x02) => "update-chunk",
        (0x08, 0x03) => "update-finalize",
        (0x08, 0x04) => "update-activate",
        (0x08, 0x05) => "update-recover",
        _ => "unknown",
    }
}

fn audit_result_class_name(value: u8) -> &'static str {
    match value {
        0x01 => "success",
        0x02 => "command-unavailable",
        0x03 => "state-denied",
        0x04 => "authorization-denied",
        0x05 => "key-policy-denied",
        0x06 => "approval-required",
        0x07 => "approval-stale",
        0x08 => "failed-closed",
        _ => "unknown",
    }
}

fn audit_detail_text(detail: &[u8]) -> String {
    if detail.is_empty() {
        "none".to_string()
    } else {
        hex_bytes(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CliError, CommandOutput, ErrorKind, ExitStatus, TransportCondition, audit_page_lines,
        lines_output,
    };
    use crate::client::{AuditEntryRecord, AuditPage};

    #[test]
    fn lines_output_joins_with_newlines() {
        let output = lines_output(&["one".into(), "two".into()]).into_stdout();
        assert_eq!(output, b"one\ntwo\n");
    }

    #[test]
    fn bytes_output_round_trips() {
        let output = CommandOutput::Bytes(vec![1, 2, 3]).into_stdout();
        assert_eq!(output, vec![1, 2, 3]);
    }

    #[test]
    fn usage_error_uses_usage_exit_code() {
        let err = CliError::usage("bad args");
        assert_eq!(err.exit_status, ExitStatus::Usage);
        assert_eq!(err.kind, ErrorKind::Usage);
    }

    #[test]
    fn audit_page_output_is_bounded_and_human_readable() {
        let lines = audit_page_lines(
            "/dev/test",
            &AuditPage {
                entries: vec![AuditEntryRecord {
                    sequence_id: 7,
                    event_class: 0x05,
                    event_code: 0x07,
                    device_revision: 11,
                    lifecycle_state: 0x03,
                    actor_role: 0x03,
                    session_kind: 0x03,
                    result_class: 0x01,
                    detail: vec![0x0c, 0x02],
                }],
                next_sequence: Some(8),
                truncated: true,
            },
            false,
        );
        assert_eq!(lines[0], "Device: /dev/test");
        assert_eq!(lines[1], "Entries: 1");
        assert_eq!(lines[3], "Truncated: yes");
        assert_eq!(lines[5], "Sequence 7 | administrator session");
        assert_eq!(lines[6], "  Event: policy / unknown");
        assert_eq!(lines[7], "  Actor: administrator");
        assert_eq!(lines[8], "  Result: success");
        assert_eq!(lines[9], "  Detail: 0c02");
    }

    #[test]
    fn audit_page_one_line_output_is_dense() {
        let lines = audit_page_lines(
            "/dev/test",
            &AuditPage {
                entries: vec![AuditEntryRecord {
                    sequence_id: 7,
                    event_class: 0x05,
                    event_code: 0x07,
                    device_revision: 11,
                    lifecycle_state: 0x03,
                    actor_role: 0x03,
                    session_kind: 0x03,
                    result_class: 0x01,
                    detail: vec![0x0c, 0x02],
                }],
                next_sequence: Some(8),
                truncated: true,
            },
            true,
        );
        assert_eq!(
            lines[4],
            "#7  administrator  policy/unknown  actor=administrator  result=success  detail=0c02"
        );
    }

    #[test]
    fn transport_error_can_carry_condition() {
        let err = CliError::transport_with_condition(
            "busy",
            TransportCondition::BusyPort,
        );
        assert_eq!(err.exit_status, ExitStatus::Transport);
        assert_eq!(err.kind, ErrorKind::Transport);
        assert_eq!(err.transport_condition, Some(TransportCondition::BusyPort));
    }
}
