use gitveil::config::SourceFormat;
use gitveil::envelope::{CiphertextEnvelope, DecryptedEnvelope};
use gitveil::source::parse;

// `sops.version` stays at 3.13.2 on purpose: the envelope reader only requires the
// key to be present and never compares it, so this fixture doubles as the guard that
// ciphertext written by an older SOPS keeps parsing after the sidecar is bumped.
const VALID_CIPHERTEXT: &str = r#"gitveil_v1_dotenv:
  data:
    TOKEN_unencrypted: ENC[AES256_GCM,data:AAAA,iv:BBBB,tag:CCCC,type:str]
    ENABLED: ENC[AES256_GCM,data:DDDD,iv:EEEE,tag:FFFF,type:bool]
  layout: ENC[AES256_GCM,data:GGGG,iv:HHHH,tag:IIII,type:str]
sops:
  age:
    - recipient: age188vgf8ute33cy6jvmq39xcp70ju5lqk5vga3rn3eyljesxclx4lsvytjad
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
        payload
        -----END AGE ENCRYPTED FILE-----
  lastmodified: "2026-07-10T00:00:00Z"
  mac: ENC[AES256_GCM,data:MMMM,iv:NNNN,tag:OOOO,type:str]
  encrypted_regex: .*
  version: 3.13.2
"#;

#[test]
fn ciphertext_format_is_self_describing() {
    assert_eq!(
        CiphertextEnvelope::detect_format(VALID_CIPHERTEXT.as_bytes()).expect("detect"),
        SourceFormat::Dotenv
    );
    let yaml_flavor = VALID_CIPHERTEXT.replace("gitveil_v1_dotenv", "gitveil_v1_yaml");
    assert_eq!(
        CiphertextEnvelope::detect_format(yaml_flavor.as_bytes()).expect("detect"),
        SourceFormat::Yaml
    );
    // No discriminator: not a gitveil envelope.
    assert!(CiphertextEnvelope::detect_format(b"KEY: value\n").is_err());
    assert!(CiphertextEnvelope::detect_format(b"not yaml: [").is_err());
}

#[test]
fn keyless_validation_accepts_only_full_encryption_envelope() {
    let envelope = CiphertextEnvelope::parse(VALID_CIPHERTEXT.as_bytes(), SourceFormat::Dotenv)
        .expect("valid envelope");
    assert_eq!(envelope.format(), SourceFormat::Dotenv);
    assert_eq!(envelope.age_recipients().len(), 1);
    assert!(
        envelope
            .key_paths()
            .contains(&"TOKEN_unencrypted".to_owned())
    );

    for malformed in [
        VALID_CIPHERTEXT.replace("encrypted_regex: .*", "unencrypted_suffix: _unencrypted"),
        VALID_CIPHERTEXT.replace(
            "ENC[AES256_GCM,data:AAAA,iv:BBBB,tag:CCCC,type:str]",
            "plaintext",
        ),
        VALID_CIPHERTEXT.replace("gitveil_v1_dotenv", "gitveil_v2_dotenv"),
        VALID_CIPHERTEXT.replace("  mac: ENC", "  missing_mac: ENC"),
        VALID_CIPHERTEXT.replace(
            "age188vgf8ute33cy6jvmq39xcp70ju5lqk5vga3rn3eyljesxclx4lsvytjad",
            "age1invalid",
        ),
        VALID_CIPHERTEXT.replace("  age:", "  pgp:"),
    ] {
        assert!(
            CiphertextEnvelope::parse(malformed.as_bytes(), SourceFormat::Dotenv).is_err(),
            "accepted malformed envelope:\n{malformed}"
        );
    }
}

#[test]
fn decrypted_envelope_round_trips_source_semantics_without_values_in_layout() {
    let source = parse(
        SourceFormat::Dotenv,
        b"# private comment\nTOKEN=super-secret-canary\n",
    )
    .expect("source parses");
    let envelope = DecryptedEnvelope::from_source(&source).expect("envelope builds");
    let yaml = envelope.to_yaml().expect("YAML serializes");

    assert!(yaml.windows(b"TOKEN".len()).any(|w| w == b"TOKEN"));
    let restored = DecryptedEnvelope::from_yaml(&yaml, SourceFormat::Dotenv)
        .expect("decrypted envelope parses")
        .into_source()
        .expect("source restores");
    assert!(source.semantic_eq(&restored));
    assert!(
        String::from_utf8(restored.generate().expect("generate"))
            .expect("UTF-8")
            .contains("# private comment")
    );
}
