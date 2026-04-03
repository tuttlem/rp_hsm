use heapless::Vec;

pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 6;
pub const MAX_PAYLOAD_LEN: usize = 240;
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;

pub const FLAG_RESPONSE_REQUIRED: u8 = 0x01;
pub const FLAG_REPLAY_SENSITIVE: u8 = 0x02;
pub const FLAG_INCLUDE_RESTRICTED: u8 = 0x04;
pub const RESERVED_FLAG_MASK: u8 = !(FLAG_RESPONSE_REQUIRED | FLAG_REPLAY_SENSITIVE | FLAG_INCLUDE_RESTRICTED);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageKind {
    Request = 0x01,
    Response = 0x02,
}

impl MessageKind {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Request),
            0x02 => Some(Self::Response),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolFrame {
    pub version: u8,
    pub kind: MessageKind,
    pub code: u8,
    pub flags: u8,
    pub payload: Vec<u8, MAX_PAYLOAD_LEN>,
}

impl Default for ProtocolFrame {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            kind: MessageKind::Request,
            code: 0,
            flags: 0,
            payload: Vec::new(),
        }
    }
}

impl ProtocolFrame {
    #[must_use]
    pub fn new(kind: MessageKind, code: u8, flags: u8, payload: &[u8]) -> Option<Self> {
        let mut data = Vec::new();
        data.extend_from_slice(payload).ok()?;
        Some(Self {
            version: PROTOCOL_VERSION,
            kind,
            code,
            flags,
            payload: data,
        })
    }

    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub fn clear(&mut self) {
        for byte in &mut self.payload {
            *byte = 0;
        }
        self.payload.clear();
    }
}
