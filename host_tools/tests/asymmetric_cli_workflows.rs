use host_tools::{CommandSpec, parse_args, usage_text};

fn parse(parts: &[&str]) -> CommandSpec {
    parse_args(parts.iter().map(|value| value.to_string()))
        .expect("parse")
        .command
}

#[test]
fn parses_asymmetric_decrypt_command() {
    assert!(matches!(
        parse(&[
            "rphsmtool",
            "asym-decrypt",
            "--key-id",
            "7",
            "--algorithm",
            "x25519-chacha20poly1305",
            "--role",
            "key-manager",
            "--proof-env",
            "RPHSM_KEYMG",
        ]),
        CommandSpec::AsymDecrypt { .. }
    ));
}

#[test]
fn help_mentions_asymmetric_encryption_workflow() {
    let text = usage_text();
    assert!(text.contains("asym-encrypt"));
    assert!(text.contains("asym-decrypt"));
    assert!(text.contains("x25519-chacha20poly1305"));
}
