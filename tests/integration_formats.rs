pub mod support;

use std::fs;

use gitveil::config::SourceFormat;
use gitveil::source::parse;
use support::{GitFixture, assert_success, contains};

const CANARY: &str = "gitveil-secret-format-canary";

/// The open path renders through the source generator; comparing against the
/// generator's own round trip keeps this test about seal/open, not about
/// generator normalization choices.
fn normalized(format: SourceFormat, body: &str) -> String {
    String::from_utf8(
        parse(format, body.as_bytes())
            .expect("parse body")
            .generate()
            .expect("generate body"),
    )
    .expect("utf-8")
}

#[test]
fn all_four_formats_round_trip_losslessly_through_seal_and_open() {
    let fixture = GitFixture::new();
    fixture.write_manifest(&[
        ("secret.env", "dotenv"),
        ("secret.json", "json"),
        ("secret.yaml", "yaml"),
        ("secret.toml", "toml"),
    ]);
    let bodies = [
        (
            "secret.env",
            SourceFormat::Dotenv,
            format!("# dotenv comment\nA={CANARY}\nB=stable\n"),
        ),
        (
            "secret.json",
            SourceFormat::Json,
            format!("{{\n  \"a\": \"{CANARY}\",\n  \"nested\": {{ \"n\": 1 }}\n}}\n"),
        ),
        (
            "secret.yaml",
            SourceFormat::Yaml,
            format!("# yaml comment\na: {CANARY}\nnested:\n  n: 1\n"),
        ),
        (
            "secret.toml",
            SourceFormat::Toml,
            format!("# toml comment\na = \"{CANARY}\"\n\n[nested]\nn = 1\n"),
        ),
    ];
    for (path, _, body) in &bodies {
        fs::write(fixture.root().join(path), body).expect("write plaintext");
    }
    assert_success(fixture.run_gitveil(&["seal"]), "seal all formats");
    for (path, _, _) in &bodies {
        let ciphertext =
            fs::read(fixture.root().join(format!("{path}.gitveil"))).expect("ciphertext");
        assert!(
            !contains(&ciphertext, CANARY.as_bytes()),
            "{path}: value must be encrypted"
        );
        fs::remove_file(fixture.root().join(path)).expect("remove plaintext");
    }
    assert_success(fixture.run_gitveil(&["open"]), "open all formats");
    for (path, format, body) in &bodies {
        let restored = fs::read_to_string(fixture.root().join(path)).expect("restored plaintext");
        assert_eq!(
            restored,
            normalized(*format, body),
            "{path} must round trip through the generator"
        );
    }
}
