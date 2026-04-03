pub mod cli;
pub mod client;

pub use cli::args::{
    AuthOptions, CommandSpec, GlobalOptions, ParsedArgs, all_usage_text, parse_args, usage_text,
};
pub use cli::device::{
    DiscoveredDevice, discover_devices, looks_like_candidate, no_compatible_devices_message,
    resolve_device_selector,
};
pub use cli::output::{CliError, CommandOutput, ErrorKind, ExitStatus, TransportCondition};
pub use client::{
    AuditEntryRecord, AuditPage, ClientConfig, DeveloperFaultAction, FirmwareUpdateActivation,
    FirmwareUpdateBegin, FirmwareUpdateProgress, FirmwareVersionInput, KeyListRecord,
    PolicyProfileUpdate, ProbeInfo, ProvisionResult, Role, SerialBackend, SessionContext,
    StatusReport, VerifyAlgorithm,
};
