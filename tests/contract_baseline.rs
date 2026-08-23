use gitveil::baseline::{BaselineRecord, CipherSummary, unit_view};
use gitveil::config::SourceFormat;
use gitveil::envelope::CiphertextEnvelope;
use gitveil::source::parse;

const SALT: [u8; 32] = [7; 32];
const CANARY: &str = "gitveil-baseline-canary-value";

fn document(body: &str) -> gitveil::source::SourceDocument {
    parse(SourceFormat::Dotenv, body.as_bytes()).expect("document")
}

// `sops.version` stays at 3.13.2 on purpose; see the note in `contract_envelope.rs`.
fn envelope(leaf_a: &str, leaf_b: &str, layout: &str) -> CiphertextEnvelope {
    let text = format!(
        "gitveil_v1_dotenv:\n  data:\n    A: ENC[AES256_GCM,data:{leaf_a},iv:BB,tag:CC,type:str]\n    B: ENC[AES256_GCM,data:{leaf_b},iv:BB,tag:CC,type:str]\n  layout: ENC[AES256_GCM,data:{layout},iv:HH,tag:II,type:str]\nsops:\n  age:\n    - recipient: age188vgf8ute33cy6jvmq39xcp70ju5lqk5vga3rn3eyljesxclx4lsvytjad\n      enc: payload\n  lastmodified: \"2026-07-18T00:00:00Z\"\n  mac: ENC[AES256_GCM,data:MM,iv:NN,tag:OO,type:str]\n  encrypted_regex: .*\n  version: 3.13.2\n"
    );
    CiphertextEnvelope::parse(text.as_bytes(), SourceFormat::Dotenv).expect("envelope")
}

fn summary() -> CipherSummary {
    CipherSummary::from_envelope(&envelope("AA", "AB", "GG"))
}

#[test]
fn capture_answers_key_and_layout_equivalence() {
    let base = document(&format!("# comment\nA={CANARY}\nB=two\n"));
    let record = BaselineRecord::capture(&base, &summary(), SALT);

    // Unchanged document matches everywhere.
    let same = document(&format!("# comment\nA={CANARY}\nB=two\n"));
    assert_eq!(
        record.unit_matches("A", unit_view(&same, "A").as_ref()),
        Some(true)
    );
    assert_eq!(
        record.unit_matches("B", unit_view(&same, "B").as_ref()),
        Some(true)
    );
    assert!(record.residual_layout_matches(&same));

    // A changed value is detected per unit.
    let changed = document("# comment\nA=changed\nB=two\n");
    assert_eq!(
        record.unit_matches("A", unit_view(&changed, "A").as_ref()),
        Some(false)
    );
    assert_eq!(
        record.unit_matches("B", unit_view(&changed, "B").as_ref()),
        Some(true)
    );

    // A comment attached to a key belongs to that key's unit.
    let comment_changed = document(&format!("# different comment\nA={CANARY}\nB=two\n"));
    assert_eq!(
        record.unit_matches("A", unit_view(&comment_changed, "A").as_ref()),
        Some(false)
    );
    assert!(record.residual_layout_matches(&comment_changed));

    // A trailing file comment is residual layout, not any key's unit.
    let tail_changed = document(&format!("# comment\nA={CANARY}\nB=two\n# tail\n"));
    assert_eq!(
        record.unit_matches("A", unit_view(&tail_changed, "A").as_ref()),
        Some(true)
    );
    assert!(!record.residual_layout_matches(&tail_changed));

    // Unknown keys answer None so callers can distinguish additions.
    assert_eq!(
        record.unit_matches("NEW", unit_view(&changed, "NEW").as_ref()),
        None
    );
    assert!(!record.has_key("NEW"));
    assert!(record.has_key("A"));
}

#[test]
fn digests_are_salt_dependent_and_leak_no_values() {
    let base = document(&format!("A={CANARY}\n"));
    let record = BaselineRecord::capture(&base, &summary(), SALT);
    let other_salt = BaselineRecord::capture(&base, &summary(), [9; 32]);

    let serialized = record.to_json().expect("serialize");
    let text = String::from_utf8(serialized.clone()).expect("utf-8");
    assert!(
        !text.contains(CANARY),
        "baseline must not contain plaintext values"
    );

    let restored = BaselineRecord::from_json(&serialized).expect("round trip");
    assert_eq!(
        restored.unit_matches("A", unit_view(&base, "A").as_ref()),
        Some(true)
    );

    let foreign = other_salt.to_json().expect("serialize");
    assert_ne!(
        serialized, foreign,
        "different salts must produce different digests"
    );
}

#[test]
fn cipher_side_diff_detects_unit_changes_without_decryption() {
    let base = document("A=1\nB=2\n");
    let record = BaselineRecord::capture(&base, &summary(), SALT);

    let same = CipherSummary::from_envelope(&envelope("AA", "AB", "GG"));
    assert!(record.diff_cipher(&same).is_empty());

    // One leaf re-encrypted: only that unit reports as changed.
    let changed = CipherSummary::from_envelope(&envelope("ZZ", "AB", "GG"));
    let diff = record.diff_cipher(&changed);
    assert_eq!(diff.changed, vec!["A".to_owned()]);
    assert!(diff.added.is_empty() && diff.removed.is_empty());
    assert!(!diff.layout_changed);

    // Layout ciphertext changed: reported as a layout change.
    let layout = CipherSummary::from_envelope(&envelope("AA", "AB", "QQ"));
    assert!(record.diff_cipher(&layout).layout_changed);
}

#[test]
fn plain_side_diff_reports_changed_added_and_removed_keys() {
    let base = document("A=1\nB=2\n");
    let record = BaselineRecord::capture(&base, &summary(), SALT);
    let current = document("A=changed\nC=new\n");
    let diff = record.diff_plain(&current);
    assert_eq!(diff.changed, vec!["A".to_owned()]);
    assert_eq!(diff.added, vec!["C".to_owned()]);
    assert_eq!(diff.removed, vec!["B".to_owned()]);
    assert!(
        !diff.layout_changed,
        "per-key changes must not count as residual layout drift"
    );
}

#[test]
fn corrupt_serialized_records_are_rejected() {
    assert!(BaselineRecord::from_json(b"not json").is_err());
    assert!(BaselineRecord::from_json(br#"{"version":99}"#).is_err());
}

// A record whose salt does not decode to the 32 bytes every digest was
// computed with cannot arbitrate anything; it must be rejected at parse time
// instead of silently mismatching (or matching) every digest.
#[test]
fn records_with_a_corrupt_salt_are_rejected() {
    let with_salt = |salt: &str| {
        format!(
            r#"{{"version":1,"salt":"{salt}","keys":{{}},"layout":"","cipher_units":{{}},"cipher_layout":""}}"#
        )
    };
    assert!(
        BaselineRecord::from_json(with_salt("zz").as_bytes()).is_err(),
        "non-hexadecimal salt must be rejected"
    );
    assert!(
        BaselineRecord::from_json(with_salt("abcd").as_bytes()).is_err(),
        "a salt that is not 32 bytes must be rejected"
    );
    let valid = hex::encode([7_u8; 32]);
    assert!(BaselineRecord::from_json(with_salt(&valid).as_bytes()).is_ok());
}

#[test]
fn non_mapping_roots_fall_back_to_a_whole_document_unit() {
    let base = parse(SourceFormat::Json, b"[1, 2, 3]").expect("sequence document");
    let record = BaselineRecord::capture(&base, &summary(), SALT);
    let same = parse(SourceFormat::Json, b"[1, 2, 3]").expect("sequence document");
    let changed = parse(SourceFormat::Json, b"[1, 2, 4]").expect("sequence document");
    assert_eq!(
        record.unit_matches(
            BaselineRecord::ROOT_UNIT,
            unit_view(&same, BaselineRecord::ROOT_UNIT).as_ref()
        ),
        Some(true)
    );
    assert_eq!(
        record.unit_matches(
            BaselineRecord::ROOT_UNIT,
            unit_view(&changed, BaselineRecord::ROOT_UNIT).as_ref()
        ),
        Some(false)
    );
}
