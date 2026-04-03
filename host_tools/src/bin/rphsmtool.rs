use std::io::{self, Write};

use host_tools::cli::args::parse_args;
use host_tools::cli::commands::execute;

fn main() {
    let exit_code = match run(std::env::args().collect()) {
        Ok(()) => 0,
        Err((message, code)) => {
            let _ = writeln!(io::stderr(), "{message}");
            code
        }
    };
    std::process::exit(exit_code);
}

fn run(args: Vec<String>) -> Result<(), (String, i32)> {
    let parsed = parse_args(args).map_err(|err| (err.to_string(), err.exit_status as i32))?;
    let output = execute(parsed).map_err(|err| (err.to_string(), err.exit_status as i32))?;
    io::stdout()
        .write_all(&output.into_stdout())
        .map_err(|err| (format!("failed to write stdout: {err}"), 8))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn help_like_invocation_returns_usage_error() {
        let err = run(vec!["rphsmtool".into()]).expect_err("must fail");
        assert!(err.0.contains("Usage:"));
    }

    #[test]
    fn unsupported_command_returns_nonzero() {
        let err = run(vec!["rphsmtool".into(), "sym-encrypt".into()]).expect_err("must fail");
        assert_ne!(err.1, 0);
    }
}
