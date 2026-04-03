use std::fmt;

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

#[cfg(test)]
mod tests {
    use super::{CliError, CommandOutput, ExitStatus, lines_output};

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
}
