use gitveil::config::SourceFormat;
use gitveil::source::{Layout, LineEnding, Node, Scalar, SourceDocument, SourceError, parse};

#[test]
fn dotenv_preserves_comments_order_export_and_crlf() {
    let input = b"# database credential\r\nexport DATABASE_URL='postgres://secret' # primary\r\nENABLED=true\r\n";
    let document = parse(SourceFormat::Dotenv, input).expect("dotenv parses");

    let keys = document.root().mapping_keys().expect("mapping");
    assert_eq!(keys, vec!["DATABASE_URL", "ENABLED"]);
    assert_eq!(
        document.root().get("ENABLED"),
        Some(&Node::Scalar(Scalar::String("true".into())))
    );

    let generated = document.generate().expect("dotenv generates");
    assert!(generated.windows(2).all(|w| w != b"\n\n") || generated.contains(&b'\r'));
    let generated = String::from_utf8(generated).expect("UTF-8");
    assert!(generated.contains("# database credential\r\n"));
    assert!(generated.contains("export DATABASE_URL="));
    assert!(generated.contains("# primary\r\n"));
    assert!(generated.find("DATABASE_URL").unwrap() < generated.find("ENABLED").unwrap());
}

#[test]
fn json_preserves_order_and_scalar_types() {
    let document = parse(
        SourceFormat::Json,
        br#"{"string":"1","number":1,"bool":true,"none":null,"nested":{"z":2}}"#,
    )
    .expect("JSON parses");

    assert_eq!(
        document.root().mapping_keys().expect("mapping"),
        vec!["string", "number", "bool", "none", "nested"]
    );
    assert!(matches!(
        document.root().get("string"),
        Some(Node::Scalar(Scalar::String(_)))
    ));
    assert!(matches!(
        document.root().get("number"),
        Some(Node::Scalar(Scalar::Integer(_)))
    ));
    assert!(matches!(
        document.root().get("bool"),
        Some(Node::Scalar(Scalar::Bool(true)))
    ));

    let reparsed = parse(SourceFormat::Json, &document.generate().expect("generate"))
        .expect("generated JSON parses");
    assert!(document.semantic_eq(&reparsed));
}

#[test]
fn yaml_preserves_comment_tag_anchor_alias_and_rejects_complex_key() {
    let input = br"# service secret
defaults: &defaults
  token: !secret abc
service:
  <<: *defaults
";
    let document = parse(SourceFormat::Yaml, input).expect("YAML parses");
    let generated = String::from_utf8(document.generate().expect("generate")).expect("UTF-8");
    assert!(generated.contains("# service secret"));
    assert!(generated.contains("&defaults"));
    assert!(generated.contains("*defaults"));
    assert!(generated.contains("!secret"));
    assert!(
        document
            .root()
            .get("service")
            .and_then(|service| service.get("<<"))
            .is_none(),
        "alias topology must not duplicate the anchor target in semantic data"
    );

    for invalid in [
        b"? [a, b]\n: secret\n".as_slice(),
        b"1: secret\n".as_slice(),
        b"true: secret\n".as_slice(),
        b"null: secret\n".as_slice(),
    ] {
        assert!(
            parse(SourceFormat::Yaml, invalid).is_err(),
            "accepted non-string YAML key: {:?}",
            String::from_utf8_lossy(invalid)
        );
    }
}

#[test]
fn yaml_preserves_flow_block_sequence_and_multi_document_layout() {
    let input = br#"---
root: { tagged: !secret "abc", list: [&item one, *item, two] } # inline
block: |
  first
  second
---
other:
  - true
  - null
"#;
    let document = parse(SourceFormat::Yaml, input).expect("YAML parses");
    let generated = String::from_utf8(document.generate().expect("generate")).expect("UTF-8");
    assert!(generated.contains("{ tagged:"));
    assert!(generated.contains("[&item one, *item, two]"));
    let list = document
        .root()
        .at_path(
            &gitveil::source::NodePath::root()
                .child_index(0)
                .child_key("root")
                .child_key("list"),
        )
        .expect("semantic list");
    assert!(matches!(list, gitveil::source::Node::Sequence(values) if values.len() == 2));
    assert!(generated.contains("# inline"));
    assert!(generated.contains("block: |"));
    assert_eq!(generated.matches("---").count(), 2);
    let reparsed = parse(SourceFormat::Yaml, generated.as_bytes()).expect("reparse");
    assert!(
        document.semantic_eq(&reparsed),
        "generated:\n{generated}\nbefore: {:?}\nafter: {:?}",
        document.root(),
        reparsed.root()
    );
}

#[test]
fn toml_preserves_comments_order_types_and_datetime() {
    let input = br#"# token
name = "secret" # inline
literal = 'quoted'
multiline = """line one
line two"""
literal_multiline = '''alpha
beta'''
count = 3
when = 1979-05-27T07:32:00Z

[service]
enabled = true
"#;
    let document = parse(SourceFormat::Toml, input).expect("TOML parses");
    let generated = String::from_utf8(document.generate().expect("generate")).expect("UTF-8");
    assert!(generated.contains("# token"));
    assert!(generated.contains("# inline"));
    assert!(generated.contains("literal = 'quoted'"));
    assert!(generated.contains("multiline = \"\"\""));
    assert!(generated.contains("literal_multiline = '''"));
    assert!(generated.find("name").unwrap() < generated.find("count").unwrap());
    assert!(generated.contains("1979-05-27T07:32:00Z"));
}

#[test]
fn every_adapter_rejects_duplicate_keys_and_non_utf8() {
    let duplicates: &[(SourceFormat, &[u8])] = &[
        (SourceFormat::Dotenv, b"A=one\nA=two\n"),
        (SourceFormat::Json, br#"{"a":1,"a":2}"#),
        (SourceFormat::Yaml, b"a: one\na: two\n"),
        (SourceFormat::Toml, b"a = 1\na = 2\n"),
    ];

    for (format, input) in duplicates {
        assert!(parse(*format, input).is_err(), "{format:?}");
    }

    for format in [
        SourceFormat::Dotenv,
        SourceFormat::Json,
        SourceFormat::Yaml,
        SourceFormat::Toml,
    ] {
        assert!(parse(format, &[0xff, 0xfe]).is_err(), "{format:?}");
    }
}

#[test]
fn dotenv_layout_merges_comments_attached_to_different_keys() {
    let base = parse(SourceFormat::Dotenv, b"# a base\nA=one\n# b base\nB=two\n").expect("base");
    let ours = parse(SourceFormat::Dotenv, b"# a ours\nA=one\n# b base\nB=two\n").expect("ours");
    let theirs = parse(
        SourceFormat::Dotenv,
        b"# a base\nA=one\n# b theirs\nB=two\n",
    )
    .expect("theirs");
    let layout =
        gitveil::source::Layout::merge_three_way(base.layout(), ours.layout(), theirs.layout())
            .expect("different comments merge");
    let merged =
        gitveil::source::SourceDocument::new(SourceFormat::Dotenv, base.root().clone(), layout);
    let generated = String::from_utf8(merged.generate().expect("generate")).expect("UTF-8");
    assert!(generated.contains("# a ours"));
    assert!(generated.contains("# b theirs"));
}

#[test]
fn dotenv_layout_merges_different_key_additions() {
    let base = parse(SourceFormat::Dotenv, b"A=one\n").expect("base");
    let ours = parse(SourceFormat::Dotenv, b"A=one\nB=two\n").expect("ours");
    let theirs = parse(SourceFormat::Dotenv, b"A=one\nC=three\n").expect("theirs");
    let layout =
        gitveil::source::Layout::merge_three_way(base.layout(), ours.layout(), theirs.layout())
            .expect("different additions merge");
    assert_eq!(
        layout
            .dotenv()
            .iter()
            .map(|entry| entry.key.as_str())
            .collect::<Vec<_>>(),
        vec!["A", "B", "C"]
    );
}

#[test]
fn toml_layout_merges_inline_comments_attached_to_different_keys() {
    let base = parse(
        SourceFormat::Toml,
        b"a = 'one' # a base\nb = 'two' # b base\n",
    )
    .expect("base");
    let ours = parse(
        SourceFormat::Toml,
        b"a = 'one' # a ours\nb = 'two' # b base\n",
    )
    .expect("ours");
    let theirs = parse(
        SourceFormat::Toml,
        b"a = 'one' # a base\nb = 'two' # b theirs\n",
    )
    .expect("theirs");
    let layout =
        gitveil::source::Layout::merge_three_way(base.layout(), ours.layout(), theirs.layout())
            .expect("different TOML comments merge");
    let merged =
        gitveil::source::SourceDocument::new(SourceFormat::Toml, base.root().clone(), layout);
    let generated = String::from_utf8(merged.generate().expect("generate")).expect("UTF-8");
    assert!(generated.contains("# a ours"));
    assert!(generated.contains("# b theirs"));
}

#[test]
fn unresolved_conflict_markers_are_rejected() {
    let input = b"<<<<<<< ours\nA=one\n=======\nA=two\n>>>>>>> theirs\n";
    assert!(parse(SourceFormat::Dotenv, input).is_err());
}

#[test]
fn yaml_generate_without_layout_template_fails_closed() {
    // Every product path (parse, envelope restore, three-way layout merge)
    // carries a template; a template-less document is a contract violation
    // and must not fall back to a lossy serializer.
    let document = SourceDocument::new(
        SourceFormat::Yaml,
        Node::Scalar(Scalar::String("secret".to_owned())),
        Layout::new(LineEnding::Lf, true),
    );
    assert!(matches!(
        document.generate(),
        Err(SourceError::Generate { .. })
    ));
}

#[test]
fn yaml_empty_document_round_trips_as_null_root() {
    let document = parse(SourceFormat::Yaml, b"").expect("empty yaml");
    let generated = document.generate().expect("generate empty yaml");
    let reparsed = parse(SourceFormat::Yaml, &generated).expect("reparse empty yaml");
    assert!(document.semantic_eq(&reparsed));
}

#[test]
fn dotenv_unquoted_values_with_inner_quotes_render_verbatim() {
    // An unquoted value may contain quote characters, commas, and equals
    // signs; rendering must be a byte fixed point so a materialized file
    // re-parses to the identical document (and third-party dotenv loaders
    // never see gitveil-invented escaping).
    for text in [
        b"A=alice:\"tok=1\",bob:\"tok=2\"\n".as_slice(),
        b"A=it's-a-token\n".as_slice(),
        b"A=#leading-hash\n".as_slice(),
    ] {
        let parsed = parse(SourceFormat::Dotenv, text).expect("parse");
        let rendered = parsed.generate().expect("generate");
        assert_eq!(
            rendered.as_slice(),
            text,
            "unquoted value must render byte-identically"
        );
        let reparsed = parse(SourceFormat::Dotenv, &rendered).expect("reparse");
        assert!(parsed.semantic_eq(&reparsed));
    }
}
