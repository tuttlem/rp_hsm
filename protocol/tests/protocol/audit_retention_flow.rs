use rp_hsm::protocol::{
    AuditEventClass, AuditEventCode, AuditJournal, AuditResultClass, AuthorityRole, DeviceState,
    SessionState, MAX_AUDIT_EVENTS,
};

#[test]
#[allow(clippy::expect_used, clippy::panic)]
fn overflow_retains_newest_window_and_sets_overflow_indicator() {
    let mut journal = AuditJournal::new();
    for seq in 0..(MAX_AUDIT_EVENTS + 3) {
        journal.record(
            AuditEventClass::ObservabilityAccess,
            AuditEventCode::HealthStatusViewed,
            u32::try_from(seq).unwrap_or(0),
            DeviceState::Operational,
            AuthorityRole::Administrator,
            SessionState::Administrator,
            AuditResultClass::Success,
            &[0x0c],
        );
    }

    assert!(journal.overflow_detected());
    assert_eq!(usize::from(journal.events_retained()), MAX_AUDIT_EVENTS);
    let Ok((page, cursor)) = journal.page(0, 4) else {
        panic!("audit page unexpectedly unavailable");
    };
    assert_eq!(page.len(), 4);
    assert!(cursor.truncated);
    assert!(page[0].sequence_id > 1);
}
