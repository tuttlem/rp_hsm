# Approved Artifact Template

## Artifact Record Header

- `release_decision`: `approved`
- `approval_timestamp`:
- `approver_set`:
- `approval_basis`:

## Approved Artifact Identity

- `artifact_name`:
- `artifact_version`:
- `artifact_path`:
- `artifact_hash`:
- `source_commit`:
- `source_ref`:
- `target_triple`:
- `feature_flags`:

## Approval Basis

- `release_evidence_record`:
- `candidate_id`:
- `candidate_scope`:
- `hardening_matrix_summary`:

## Dependency Review Snapshot

- `cargo_lock_changed`:
- `changed_crates`:
- `security_relevant_boundaries_touched`:
- `review_conclusion`:

## Build Review Snapshot

- `build_commands`:
- `build_host`:
- `rustc_version`:
- `cargo_version`:
- `artifact_provenance_notes`:

## Carried Exceptions

- `exception_id`:
- `affected_check_ids`:
- `mitigation`:
- `expiry_or_revisit_trigger`:

## Approval Notes

- `unresolved_risks_visible_to_operators`:
- `release_note_reference`:
- `post_release_follow_up`:
