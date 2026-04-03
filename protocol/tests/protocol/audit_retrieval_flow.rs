use rp_hsm::protocol::{DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode, encode_frame};

use super::crypto_fixtures::{authorized, begin_auth, complete_auth, request};

fn request_health(engine: &mut ProtocolEngine) {
    let _ = engine.handle_bytes(
        &encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default())
            .unwrap_or_default(),
    );
}

fn next_sequence(payload: &[u8]) -> Option<u32> {
    if payload[1] == 0 {
        None
    } else {
        Some(u32::from_le_bytes([payload[2], payload[3], payload[4], payload[5]]))
    }
}

fn sequence_bytes(sequence: u32) -> [u8; 4] {
    sequence.to_le_bytes()
}

#[test]
#[allow(clippy::expect_used, clippy::panic)]
fn audit_page_cursor_advances_monotonically() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    for _ in 0..6 {
        request_health(&mut engine);
    }

    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    let first = engine.handle_bytes(&request(
        0x0d,
        0x02,
        &authorized(session, 2, &[0, 0, 0, 0, 4]),
    ));
    assert_eq!(first.code, StatusCode::Success.as_u8());
    assert_eq!(first.payload[0], 4);
    let Some(next) = next_sequence(first.payload.as_slice()) else {
        panic!("expected a follow-on audit cursor");
    };
    let next_bytes = sequence_bytes(next);

    let second = engine.handle_bytes(&request(
        0x0d,
        0x02,
        &authorized(
            session,
            3,
            &[next_bytes[0], next_bytes[1], next_bytes[2], next_bytes[3], 4],
        ),
    ));
    assert_eq!(second.code, StatusCode::Success.as_u8());
    assert!(second.payload[0] >= 1);
}
