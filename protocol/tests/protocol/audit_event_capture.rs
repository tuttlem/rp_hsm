use rp_hsm::protocol::{DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode, encode_frame};

use super::crypto_fixtures::{authorized, begin_auth, complete_auth, request};

fn decode_page_sequences(payload: &[u8]) -> Vec<u32> {
    let entry_count = usize::from(payload[0]);
    let mut offset = 6usize;
    let mut sequences = Vec::new();
    for _ in 0..entry_count {
        let sequence = u32::from_le_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]);
        sequences.push(sequence);
        let detail_len = usize::from(payload[offset + 13]);
        offset += 14 + detail_len;
    }
    sequences
}

#[test]
fn health_and_denial_paths_generate_auditable_events() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);

    let _ = engine.handle_bytes(
        &encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default())
            .unwrap_or_default(),
    );
    let _ = engine.handle_bytes(&request(
        0x80,
        0x02,
        &authorized([0, 0, 0, 0], 1, b"lab"),
    ));

    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    let response = engine.handle_bytes(&request(
        0x0d,
        0x02,
        &authorized(session, 2, &[0, 0, 0, 0, 4]),
    ));
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert!(response.payload[0] >= 2);
    let sequences = decode_page_sequences(response.payload.as_slice());
    assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
}
