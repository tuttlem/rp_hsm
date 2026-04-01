pub mod codec;
pub mod command;
pub mod frame;
pub mod parser;
pub mod state;

pub use codec::{DecodeError, StatusCode, decode_frame, encode_frame};
pub use command::{
    CommandDefinition, CommandFamily, CommandId, IdempotencyPolicy, ReplayPolicy,
    get_public_catalog,
};
pub use frame::{
    FLAG_INCLUDE_RESTRICTED, FLAG_REPLAY_SENSITIVE, FLAG_RESPONSE_REQUIRED, HEADER_LEN,
    MAX_FRAME_LEN, MAX_PAYLOAD_LEN, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
    RESERVED_FLAG_MASK,
};
pub use parser::{ProtocolEngine, clear_transient_buffer};
pub use state::{DeviceState, SessionState, SessionTracker};
