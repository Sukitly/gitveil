use bech32::{Bech32, Hrp};
use gitveil::config::SourceFormat;
use gitveil::manifest::{CIPHERTEXT_SUFFIX, GITIGNORE_FILE_NAME, MANIFEST_FILE_NAME, Manifest};
use gitveil::path::ManagedPath;
use gitveil::profile::ProfileName;

fn recipient(seed: u8) -> String {
    let hrp = Hrp::parse("age").expect("valid age recipient HRP");
    bech32::encode::<Bech32>(hrp, &[seed; 32]).expect("valid test recipient")
}

fn manifest_json(files: &str, policies: &str) -> Vec<u8> {
    format!(
        "{{\n  \"version\": 1,\n  \"recipientPolicies\": {{{policies}}},\n  \"files\": [{files}]\n}}"
    )
    .into_bytes()
}

fn entry(path: &str, format: &str, policy: &str) -> String {
    format!(
        "{{ \"path\": \"{path}\", \"format\": \"{format}\", \"recipientPolicy\": \"{policy}\" }}"
    )
}

fn profiled_entry(path: &str, format: &str, policy: &str, profile: &str) -> String {
    format!(
        "{{ \"path\": \"{path}\", \"format\": \"{format}\", \"recipientPolicy\": \"{policy}\", \"profile\": \"{profile}\" }}"
    )
}

fn policy(name: &str, recipients: &[String]) -> String {
    let recipients = recipients
        .iter()
        .map(|recipient| format!("\"{recipient}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("\"{name}\": {{ \"age\": [{recipients}] }}")
}

#[test]
fn manifest_constants_match_specification() {
    assert_eq!(MANIFEST_FILE_NAME, ".gitveilrc.json");
    assert_eq!(GITIGNORE_FILE_NAME, ".gitignore");
    assert_eq!(CIPHERTEXT_SUFFIX, ".gitveil");
}

#[test]
fn parses_versioned_entries_with_named_age_recipient_policies() {
    let team_recipient = recipient(1);
    let prod_recipients = [recipient(2), recipient(3)];
    let policies = format!(
        "{}, {}",
        policy("team", std::slice::from_ref(&team_recipient)),
        policy("prod", &prod_recipients)
    );
    let files = format!(
        "{}, {}",
        entry("packages/service/.env", "dotenv", "team"),
        entry("config/settings.yaml", "yaml", "prod")
    );
    let manifest = Manifest::parse(&manifest_json(&files, &policies)).expect("valid manifest");

    let entries = manifest.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path().as_str(), "packages/service/.env");
    assert_eq!(entries[0].format(), SourceFormat::Dotenv);
    assert_eq!(
        entries[0].ciphertext_path().as_str(),
        "packages/service/.env.gitveil"
    );
    assert_eq!(entries[0].recipient_policy().as_str(), "team");
    assert_eq!(entries[0].profile().as_str(), "default");
    let team = manifest
        .recipient_policy(entries[0].recipient_policy())
        .expect("referenced policy");
    assert_eq!(team.recipients()[0].as_str(), team_recipient);
    assert_eq!(entries[1].format(), SourceFormat::Yaml);
    assert_eq!(entries[1].recipient_policy().as_str(), "prod");
    let prod = manifest
        .recipient_policy(entries[1].recipient_policy())
        .expect("referenced policy");
    assert_eq!(prod.recipients().len(), 2);
}

#[test]
fn empty_file_and_policy_maps_are_valid() {
    let manifest = Manifest::parse(&manifest_json("", "")).expect("empty manifest");
    assert!(manifest.entries().is_empty());
}

#[test]
fn missing_and_explicit_profiles_parse_to_typed_names() {
    let recipient = recipient(1);
    let files = format!(
        "{}, {}, {}",
        entry("default.env", "dotenv", "team"),
        profiled_entry("explicit.env", "dotenv", "team", "default"),
        profiled_entry("dev.env", "dotenv", "team", "dev")
    );
    let manifest = Manifest::parse(&manifest_json(&files, &policy("team", &[recipient])))
        .expect("profiled manifest");

    assert_eq!(manifest.entries()[0].profile(), &ProfileName::default());
    assert_eq!(manifest.entries()[1].profile(), &ProfileName::default());
    assert_eq!(manifest.entries()[2].profile().as_str(), "dev");
}

#[test]
fn profile_names_are_lowercase_kebab_case_with_a_bounded_length() {
    for valid in ["default", "dev", "prod-us-2", "dev--prod"] {
        assert!(ProfileName::new(valid).is_ok(), "must accept {valid:?}");
    }
    assert!(ProfileName::new(format!("a{}", "0".repeat(63))).is_ok());
    for invalid in ["", "Dev", "1dev", "dev_env", "-dev"] {
        assert!(
            ProfileName::new(invalid).is_err(),
            "must reject {invalid:?}"
        );
    }
    assert!(ProfileName::new(format!("a{}", "0".repeat(64))).is_err());
}

#[test]
fn manifest_selection_supports_profiles_paths_and_their_constrained_intersection() {
    let recipient = recipient(1);
    let files = [
        profiled_entry("dev-a.env", "dotenv", "team", "dev"),
        profiled_entry("dev-b.env", "dotenv", "team", "dev"),
        profiled_entry("prod.env", "dotenv", "team", "prod"),
        entry("shared.env", "dotenv", "team"),
    ]
    .join(", ");
    let manifest = Manifest::parse(&manifest_json(&files, &policy("team", &[recipient])))
        .expect("profiled manifest");
    let dev = ProfileName::new("dev").expect("dev profile");

    let selected = manifest.select(&[], Some(&dev)).expect("select dev");
    assert_eq!(
        selected
            .iter()
            .map(|entry| entry.path().as_str())
            .collect::<Vec<_>>(),
        ["dev-a.env", "dev-b.env"]
    );

    let subset = [ManagedPath::new("dev-b.env").expect("managed path")];
    let selected = manifest
        .select(&subset, Some(&dev))
        .expect("select dev subset");
    assert_eq!(selected[0].path().as_str(), "dev-b.env");

    let prod = [ManagedPath::new("prod.env").expect("managed path")];
    let mismatch = manifest
        .select(&prod, Some(&dev))
        .expect_err("prod must not pass a dev selector")
        .to_string();
    assert!(mismatch.contains("prod.env"));
    assert!(mismatch.contains("dev"));

    let unknown = ProfileName::new("staging").expect("valid profile name");
    assert!(manifest.select(&[], Some(&unknown)).is_err());
}

#[test]
fn rejects_invalid_profile_fields_without_treating_them_as_default() {
    let recipient = recipient(1);
    let policy = policy("team", &[recipient]);
    for profile in ["null", "\"\"", "\"Dev\"", "\"dev_env\"", "17"] {
        let files = format!(
            "{{ \"path\": \"a.env\", \"format\": \"dotenv\", \"recipientPolicy\": \"team\", \"profile\": {profile} }}"
        );
        assert!(
            Manifest::parse(&manifest_json(&files, &policy)).is_err(),
            "must reject profile {profile}"
        );
    }
}

#[test]
fn rejects_legacy_unknown_version_and_incomplete_schemas() {
    let valid_recipient = recipient(1);
    let valid_policy = policy("team", &[valid_recipient]);
    let valid_entry = entry("a.env", "dotenv", "team");
    for input in [
        // A legacy recipient-less manifest must not fall back to .sops.yaml.
        br#"{ "files": [ { "path": "a.env", "format": "dotenv" } ] }"#.as_slice(),
        br#"{ "version": 2, "recipientPolicies": {}, "files": [] }"#.as_slice(),
        br#"{ "version": 1, "files": [] }"#.as_slice(),
        br#"{ "version": 1, "recipientPolicies": {} }"#.as_slice(),
        br#"{ "version": 1, "recipientPolicies": {}, "files": [], "extra": true }"#.as_slice(),
        b"not json".as_slice(),
    ] {
        assert!(Manifest::parse(input).is_err(), "must reject: {input:?}");
    }

    for files in [
        // format missing
        r#"{ "path": "a.env", "recipientPolicy": "team" }"#,
        // path missing
        r#"{ "format": "dotenv", "recipientPolicy": "team" }"#,
        // policy missing
        r#"{ "path": "a.env", "format": "dotenv" }"#,
        // unknown field
        r#"{ "path": "a.env", "format": "dotenv", "recipientPolicy": "team", "x": 1 }"#,
        // string entry form
        r#""a.env""#,
        // unknown format
        r#"{ "path": "a.env", "format": "ini", "recipientPolicy": "team" }"#,
    ] {
        assert!(
            Manifest::parse(&manifest_json(files, &valid_policy)).is_err(),
            "must reject entry: {files}"
        );
    }

    assert!(
        Manifest::parse(&manifest_json(
            &valid_entry,
            "\"team\": { \"age\": [], \"x\": true }"
        ))
        .is_err()
    );
}

#[test]
fn rejects_repository_configuration_paths_as_managed_plaintext() {
    let recipient = recipient(1);
    let policy = policy("team", &[recipient]);
    for path in [MANIFEST_FILE_NAME, GITIGNORE_FILE_NAME] {
        assert!(
            Manifest::parse(&manifest_json(&entry(path, "dotenv", "team"), &policy)).is_err(),
            "must reserve {path}"
        );
    }
}

#[test]
fn rejects_invalid_policy_names_empty_duplicate_and_malformed_recipients() {
    let valid_recipient = recipient(1);
    let valid_entry = entry("a.env", "dotenv", "team");
    for policies in [
        format!("\"Team\": {{ \"age\": [\"{valid_recipient}\"] }}"),
        format!("\"team_name\": {{ \"age\": [\"{valid_recipient}\"] }}"),
        format!(
            "\"{}\": {{ \"age\": [\"{valid_recipient}\"] }}",
            "a".repeat(65)
        ),
        "\"team\": { \"age\": [] }".to_owned(),
        format!("\"team\": {{ \"age\": [\"{valid_recipient}\", \"{valid_recipient}\"] }}"),
        "\"team\": { \"age\": [\"not-an-age-recipient\"] }".to_owned(),
        format!(
            "\"team\": {{ \"age\": [\"{}\"] }}",
            valid_recipient.to_uppercase()
        ),
    ] {
        assert!(
            Manifest::parse(&manifest_json(&valid_entry, &policies)).is_err(),
            "must reject policy without exposing it as valid: {policies}"
        );
    }
}

#[test]
fn rejects_missing_policy_reference_without_rendering_recipient_values() {
    let secret_public_metadata = recipient(7);
    let error = Manifest::parse(&manifest_json(
        &entry("a.env", "dotenv", "missing"),
        &policy("team", std::slice::from_ref(&secret_public_metadata)),
    ))
    .expect_err("missing policy must fail")
    .to_string();
    assert!(error.contains("a.env"));
    assert!(error.contains("missing"));
    assert!(!error.contains(&secret_public_metadata));
}

#[test]
fn rejects_invalid_paths_duplicate_paths_and_ciphertext_suffixes() {
    let recipient = recipient(1);
    let policy = policy("team", &[recipient]);
    for path in [
        "/abs/.env",
        "../escape/.env",
        "a//b.env",
        ".git/config.env",
        "",
        "a.env.gitveil",
    ] {
        let input = manifest_json(&entry(path, "dotenv", "team"), &policy);
        assert!(
            Manifest::parse(&input).is_err(),
            "must reject path {path:?}"
        );
    }

    for second in ["a.env", "A.env"] {
        let files = format!(
            "{}, {}",
            entry("a.env", "dotenv", "team"),
            entry(second, "dotenv", "team")
        );
        assert!(Manifest::parse(&manifest_json(&files, &policy)).is_err());
    }
}

#[test]
fn finds_entries_by_plaintext_path() {
    let recipient = recipient(1);
    let manifest = Manifest::parse(&manifest_json(
        &entry("a.env", "dotenv", "team"),
        &policy("team", &[recipient]),
    ))
    .expect("manifest");
    let path = gitveil::path::ManagedPath::new("a.env").expect("path");
    assert!(manifest.find(&path).is_some());
    let missing = gitveil::path::ManagedPath::new("b.env").expect("path");
    assert!(manifest.find(&missing).is_none());
}
