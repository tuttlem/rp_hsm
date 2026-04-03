use heapless::Vec as HeaplessVec;
use rp_hsm::protocol::{
    ApprovalTargetBinding, ApprovalTicket, ApprovalTicketState, AuthorityRole, DeviceState,
    PolicyProfile, ProtectedActionClass, ProtocolEngine, SessionState, StatusCode,
};

use super::crypto_fixtures::{begin_auth, complete_auth, request};

fn authorized(session_id: [u8; 4], counter: u32, inner: &[u8]) -> Vec<u8> {
    let mut payload = std::vec::Vec::from(session_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.extend_from_slice(inner);
    payload
}

#[test]
fn conflicting_approval_tickets_fail_closed() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let profile = PolicyProfile {
        dual_control_enabled: true,
        ..PolicyProfile::default()
    };
    engine.restore_policy_profile(profile);

    let mut tickets = HeaplessVec::new();
    let _ = tickets.push(ApprovalTicket {
        ticket_id: 1,
        approval_class: ProtectedActionClass::DestructiveAdmin,
        target_binding: ApprovalTargetBinding::Device,
        target_id: 0,
        initiator_role: AuthorityRole::Administrator,
        confirmer_role: AuthorityRole::Administrator,
        initiator_session_id: 10,
        policy_revision: 1,
        device_revision: 0,
        expires_at_tick: 20,
        state: ApprovalTicketState::Pending,
    });
    let _ = tickets.push(ApprovalTicket {
        ticket_id: 2,
        approval_class: ProtectedActionClass::DestructiveAdmin,
        target_binding: ApprovalTargetBinding::Device,
        target_id: 0,
        initiator_role: AuthorityRole::Administrator,
        confirmer_role: AuthorityRole::Administrator,
        initiator_session_id: 11,
        policy_revision: 1,
        device_revision: 0,
        expires_at_tick: 20,
        state: ApprovalTicketState::Pending,
    });
    engine.restore_approval_tickets(tickets, 3);

    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    let response = engine.handle_bytes(&request(
        0x87,
        0x02,
        &authorized(session, 2, &[0xde, 0xad]),
    ));
    assert_eq!(response.code, StatusCode::InternalError.as_u8());
    assert_eq!(response.payload.as_slice(), &[0x07]);
}
