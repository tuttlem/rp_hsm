use host_tools::{CommandOutput, all_usage_text, usage_text};

#[test]
fn default_help_is_grouped_by_user_intent() {
    let text = usage_text();
    assert!(text.contains("User Commands:"));
    assert!(text.contains("Admin Commands:"));
    assert!(text.contains("Advanced Commands:"));
    assert!(text.contains("Developer Commands (development-only):"));
}

#[test]
fn all_help_includes_low_level_aliases() {
    let text = all_usage_text();
    assert!(text.contains("rphsmtool dev reset"));
    assert!(text.contains("rphsmtool key destroy"));
    assert!(text.contains("rphsmtool sym-encrypt"));
}

#[test]
fn binary_output_stays_raw() {
    assert_eq!(CommandOutput::Bytes(vec![1, 2, 3]).into_stdout(), vec![1, 2, 3]);
}
