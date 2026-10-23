use super::{mask, position, Position};

/// The positions of every `streams` in `text`, in order (`None` where it is not the customer's).
fn positions(text: &str) -> Vec<Option<Position>> {
    let b = text.as_bytes();
    text.match_indices("streams")
        .map(|(i, w)| position(b, i, i + w.len()))
        .collect()
}

#[test]
fn the_export_key_is_masked_in_each_position_a_customer_config_spells_it() {
    assert_eq!(
        positions("  sink: { module: tail, streams: [logs, costs] }\n    streams:  [metrics]\n"),
        vec![Some(Position::KeyOverAList), Some(Position::KeyOverAList)]
    );
    assert_eq!(
        positions("\"export.{name}.streams: is EMPTY\" and `export.siem.streams`"),
        vec![Some(Position::ExportPath), Some(Position::ExportPath)]
    );
    assert_eq!(
        positions(
            "dig(&doc, &[\"export\", name, \"streams\"]); \
             dig(&d, &[ \"export\", \"ok\", \"streams\" ])"
        ),
        vec![
            Some(Position::ExportKeyLiteral),
            Some(Position::ExportKeyLiteral)
        ]
    );
    assert_eq!(
        positions("    pub streams: Option<Vec<String>>,\n"),
        vec![Some(Position::TokenListField)]
    );
    assert_eq!(
        positions("\"streams: [logs, identity, decisions]\""),
        vec![Some(Position::KeyOverAList)]
    );
}

#[test]
fn every_other_streams_still_counts() {
    // A plane's section over a mapping, its dotted path, an identifier, a field of another type, a
    // literal of its own, a key path not rooted at `export`, joined spellings, a deeper path.
    for text in [
        "streams:\n  gw: {}\n",
        "streams: { fees: 1 }",
        "\"streams.fees.per_request\"",
        "fn from_parts(streams: &[u8]) -> usize { streams.len() }",
        "    streams: u16,",
        "self.streams | other.streams",
        "config_section: \"streams\",",
        "dig(&doc, &[\"planes\", name, \"streams\"])",
        "dig(&doc, &[\"export\", name, \"streams\", \"x\"])",
        "plane-streams: [a]",
        "streams_route: [a]",
        "cfg.export.siem.streams",
        "export.siem.streams.inner",
        "export..streams",
        "streams::Kind",
    ] {
        assert!(
            positions(text).iter().all(Option::is_none),
            "`{text}` is not the export key's position, so it counts"
        );
        assert_eq!(mask(text), None, "`{text}` is left as written");
    }
}

#[test]
fn the_mask_keeps_lines_and_columns_and_touches_only_the_word() {
    let text = "  sink: { streams: [logs] }\nlet streams = 1;\n";
    let masked = mask(text).expect("one key is masked");
    assert_eq!(masked.len(), text.len());
    assert_eq!(masked, "  sink: { xxxxxxx: [logs] }\nlet streams = 1;\n");
}

#[test]
fn the_migrated_store_literal_is_exempt_only_at_its_declaration() {
    use super::{frozen_literal, FROZEN_CONFIG_LITERALS};
    let f = &FROZEN_CONFIG_LITERALS[0];
    let decl = format!("pub const {}: &str = \"{}\";", f.holder, f.word);
    assert!(frozen_literal(f.file, &decl, f.word));
    assert!(frozen_literal(f.file, &format!("    {decl}"), f.word));
    for (rel, line) in [
        // Another file, the same declaration.
        ("crates/busbar-kernel/src/config/mod.rs", decl.clone()),
        // The same file: an edited declaration, another name, the word on another line.
        (
            f.file,
            format!("pub const {}_EDITED: &str = \"{}\";", f.holder, f.word),
        ),
        (f.file, format!("pub const OTHER: &str = \"{}\";", f.word)),
        (f.file, format!("{decl} // and \"{}\"", f.word)),
        (f.file, format!("let m = \"{}\";", f.word)),
    ] {
        assert!(
            !frozen_literal(rel, &line, f.word),
            "`{line}` in {rel} is not the declaration, so its literal counts"
        );
    }
}
