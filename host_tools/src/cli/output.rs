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
}

impl CliError {
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::Usage,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::NotFound,
        }
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::Unsupported,
        }
    }

    pub fn auth(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::Auth,
        }
    }

    pub fn transport(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::Transport,
        }
    }

    pub fn invalid_response(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::InvalidResponse,
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_status: ExitStatus::Failure,
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
pub fn audit_page_lines(device: &str, page: &AuditPage) -> Vec<String> {
    let mut lines = vec![
        format!("device={device}"),
        format!("entry_count={}", page.entries.len()),
        format!(
            "next_sequence={}",
            page.next_sequence
                .map_or_else(|| "none".to_string(), |value| value.to_string())
        ),
        format!("truncated={}", if page.truncated { "yes" } else { "no" }),
    ];
    for entry in &page.entries {
        lines.push(format!(
            "entry sequence={} class=0x{:02x} code=0x{:02x} device_revision={} lifecycle_state={} actor_role={} session_kind={} result_class={} detail={}",
            entry.sequence_id,
            entry.event_class,
            entry.event_code,
            entry.device_revision,
            entry.lifecycle_state,
            entry.actor_role,
            entry.session_kind,
            entry.result_class,
            hex_bytes(&entry.detail),
        ));
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

#[cfg(test)]
mod tests {
    use super::{CliError, CommandOutput, ExitStatus, audit_page_lines, lines_output};
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
        );
        assert_eq!(lines[0], "device=/dev/test");
        assert_eq!(lines[1], "entry_count=1");
        assert!(lines[3].contains("truncated=yes"));
        assert!(lines[4].contains("detail=0c02"));
    }
}
