//! One library-level negative test per defect found in the codec review.
//!
//! Deliberately **Python-free** and part of the default `cargo test` run: these
//! encode the *decisions* ("malformed input must error", "`--fill` must
//! change something"), not oracle parity, so they have to run on every machine
//! and every PR, including where `python3` is absent. Parity of these same
//! behaviours with `contrib/asmap/asmap-tool.py` is covered separately by
//! `crates/bitcoin-asmap-quorum/tests/differential_python.rs`.
//!
//! Every expected string below is the vendored Python's actual output on the
//! same input, captured while writing these tests — not a prediction.

use std::io::Cursor;

use asmap_codec::{ASMap, ASNEntry, LoadError, bits_to_network, load_file, parse_network_prefix};

/// Vector files live next to this test so `cargo test` needs no fixtures on
/// disk beyond the source tree.
fn vector(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn load(name: &str) -> Result<ASMap, LoadError> {
    load_file(Box::new(Cursor::new(vector(name))), name)
}

fn render(entries: &[ASNEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|(prefix, asn)| format!("{} AS{asn}", bits_to_network(prefix)))
        .collect()
}

// ---------------------------------------------------------------------------
// Defect 1 — a malformed text file silently produced an *empty* map.
//
// `load_file` set `entries = Some(parsed)` unconditionally, so a mid-file parse
// failure left a partial (often empty) entry list that was then treated as a
// successful text parse. `encode` exited 0 and wrote a zero-byte asmap.
// ---------------------------------------------------------------------------

#[test]
fn malformed_text_input_is_rejected() {
    let err = load("malformed.txt").expect_err("a garbage line must not parse");
    let msg = err.to_string();
    assert!(
        matches!(err, LoadError::Unrecognized { .. }),
        "expected Unrecognized, got {err:?}"
    );
    // asmap-tool.py: "... nor valid text input (unparseable line 'this is garbage')."
    assert!(
        msg.contains("unparseable line 'this is garbage'"),
        "message did not name the offending line: {msg}"
    );
}

#[test]
fn malformed_text_input_does_not_become_the_empty_map() {
    // The precise shape of the original bug: `Ok(ASMap::new())`.
    let loaded = load("malformed.txt");
    assert!(
        loaded.is_err(),
        "malformed input loaded as {:?}, and the empty map is exactly the wrong answer",
        loaded.map(|m| m.to_entries(false, false).len())
    );
}

#[test]
fn invalid_asn_token_is_rejected() {
    let err = load("bad_asn.txt").expect_err("'ASxyz' is not an ASN");
    // asmap-tool.py: "(invalid ASN 'ASxyz')"
    assert!(
        err.to_string().contains("invalid ASN 'ASxyz'"),
        "unexpected message: {err}"
    );
}

#[test]
fn well_formed_text_still_loads() {
    // Guards against "fix" by rejecting everything.
    let map = load("good.txt").expect("valid text must still load");
    assert_eq!(
        render(&map.to_entries(false, false)),
        vec![
            "1.2.3.0/24 AS64512".to_string(),
            "2.0.0.0/8 AS7".to_string()
        ],
    );
}

// ---------------------------------------------------------------------------
// Defect 2 — non-canonical prefixes were accepted and silently truncated.
//
// `ip_to_bits` masked off host bits, so `1.2.3.4/8` was read as `1.0.0.0/8`.
// `ipaddress.ip_network(..., strict=True)` in the Python rejects it.
// ---------------------------------------------------------------------------

#[test]
fn non_canonical_prefix_is_rejected() {
    let err = parse_network_prefix("1.2.3.4/8").expect_err("host bits set");
    assert_eq!(err.to_string(), "invalid network '1.2.3.4/8'");

    // Not a blanket rejection: the canonical form of the same range is fine,
    // as are a host route and the zero-length prefix.
    for ok in [
        "1.0.0.0/8",
        "1.2.3.4/32",
        "0.0.0.0/0",
        "::/0",
        "2001:db8::/32",
    ] {
        assert!(
            parse_network_prefix(ok).is_ok(),
            "{ok} is canonical and must be accepted"
        );
    }
    for bad in ["2001:db8::1/32", "1.2.3.4/24", "::1/0"] {
        assert!(
            parse_network_prefix(bad).is_err(),
            "{bad} has host bits set and must be rejected"
        );
    }
}

#[test]
fn non_canonical_prefix_is_rejected_through_load_file() {
    let err = load("non_canonical.txt").expect_err("1.2.3.4/8 has host bits set");
    // asmap-tool.py: "(invalid network '1.2.3.4/8')"
    assert!(
        err.to_string().contains("invalid network '1.2.3.4/8'"),
        "unexpected message: {err}"
    );
}

// ---------------------------------------------------------------------------
// Defect 3 — a short, valid binary asmap was reported "ambiguous".
//
// Because a failed text parse still produced `Some(entries)`, any binary file
// that happened to be valid UTF-8 satisfied both branches of the ambiguity
// check. `130028` is three bytes that are simultaneously a valid asmap and
// valid UTF-8.
// ---------------------------------------------------------------------------

#[test]
fn small_utf8_binary_asmap_is_not_ambiguous() {
    let bytes = vector("three_byte_utf8.bin");
    assert_eq!(bytes, [0x13, 0x00, 0x28], "vector changed");
    assert!(
        std::str::from_utf8(&bytes).is_ok(),
        "the vector must be valid UTF-8 or it does not test the ambiguity path"
    );
    assert!(
        ASMap::from_binary(&bytes).is_some(),
        "the vector must be a valid asmap or it does not test the ambiguity path"
    );

    let map = load("three_byte_utf8.bin").expect("must load as binary, not be called ambiguous");
    assert_eq!(render(&map.to_entries(false, true)), vec!["8000::/1 AS6"]);
}

#[test]
fn utf8_binary_is_not_ambiguous_because_the_text_parse_fails() {
    // Pins *why* the vector is unambiguous, so a future change that resurrects
    // the bug by loosening the text parser fails here rather than silently:
    // the file is unambiguous because the *text* parse fails, not because the
    // guard was weakened. `genuinely_ambiguous_input_is_still_rejected` below
    // covers the other side.
    let bytes = vector("three_byte_utf8.bin");
    let as_text = std::str::from_utf8(&bytes).expect("valid UTF-8");
    let text_parse = load_file(
        Box::new(Cursor::new(as_text.as_bytes().to_vec())),
        "as-text",
    );
    // Reading the same bytes gives the binary interpretation, never an error
    // and never a text parse.
    let map = text_parse.expect("loads");
    assert_eq!(render(&map.to_entries(false, true)), vec!["8000::/1 AS6"]);

    // And a file that *is* valid text is loaded as text, not as binary.
    let text = b"1.2.3.0/24 AS64512\n";
    assert!(
        ASMap::from_binary(text).is_none(),
        "chosen text must not also be a valid binary asmap"
    );
    let map = load_file(Box::new(Cursor::new(text.to_vec())), "text").expect("loads as text");
    assert_eq!(
        render(&map.to_entries(false, false)),
        vec!["1.2.3.0/24 AS64512"]
    );
}

/// The ambiguity guard must survive the fix to defect 3.
///
/// The vector `237c0d001c0022` — `b"#|\r\x00\x1c\x00\""` — is a real input, not
/// a construction: it fell out of the differential's own random corpus at
/// trial 304, and `asmap-tool.py decode` rejects it with the same message. It
/// satisfies both parsers at once, because it decodes as a valid asmap
/// (`3000::/4 AS8`, `4000::/2 AS18`) *and* is valid UTF-8 whose only line is a
/// comment, so the text parse succeeds with an empty entry list.
#[test]
fn genuinely_ambiguous_input_is_still_rejected() {
    let bytes = vector("ambiguous.bin");
    assert!(std::str::from_utf8(&bytes).is_ok(), "must be valid UTF-8");
    let as_binary = ASMap::from_binary(&bytes).expect("must be a valid asmap");
    assert_eq!(
        render(&as_binary.to_entries(false, true)),
        vec!["3000::/4 AS8", "4000::/2 AS18"],
    );

    let err = load("ambiguous.bin").expect_err("satisfies both parsers");
    assert!(
        matches!(err, LoadError::Ambiguous { .. }),
        "expected Ambiguous, got {err:?}"
    );
    // asmap-tool.py: "Input file '...' is ambiguous."
    assert_eq!(err.to_string(), "Input file 'ambiguous.bin' is ambiguous.");
}

// ---------------------------------------------------------------------------
// Defect 4 — `fill` was a no-op in `to_entries`.
//
// Golden vector `15ce000080a10300c0000010000070000000`. Reference output from
// the vendored `asmap.py`.
// ---------------------------------------------------------------------------

#[test]
fn fill_changes_entries() {
    let map = load("fill_differs.bin").expect("valid binary vector");

    let nofill = render(&map.to_entries(false, false));
    assert_eq!(
        nofill,
        vec![
            "4000::/3 AS2",
            "6000::/5 AS1",
            "7000::/5 AS1",
            "8000::/2 AS2",
            "c000::/3 AS1",
        ],
    );

    // `6000::/5 + 7000::/5` collapse to `6000::/3`, absorbing the unassigned
    // `6800::/5` and `7800::/5` between them. That is exactly what `fill`
    // licenses; AS0 is never emitted, with or without it.
    let filled = render(&map.to_entries(true, false));
    assert_eq!(
        filled,
        vec![
            "4000::/3 AS2",
            "6000::/3 AS1",
            "8000::/2 AS2",
            "c000::/3 AS1",
        ],
    );

    assert_ne!(nofill, filled, "fill must not be a no-op");
    assert!(
        filled.len() < nofill.len(),
        "fill exists to shorten the list"
    );
}

#[test]
fn fill_changes_entries_in_the_overlapping_form_too() {
    let map = load("fill_differs.bin").expect("valid binary vector");
    let nofill = render(&map.to_entries(false, true));
    let filled = render(&map.to_entries(true, true));
    assert_eq!(nofill.len(), 5, "overlapping fill=false");
    assert_eq!(
        filled,
        vec!["::/0 AS1", "4000::/3 AS2", "8000::/2 AS2"],
        "overlapping fill=true"
    );
    assert_ne!(nofill, filled);
}

#[test]
fn filled_entries_still_extend_the_source_map() {
    // `fill` is lossy but never *wrong*: every assignment in the source must
    // survive.
    let map = load("fill_differs.bin").expect("valid binary vector");
    for overlapping in [false, true] {
        let mut rebuilt = ASMap::new();
        rebuilt.update_multi(map.to_entries(true, overlapping));
        assert!(
            rebuilt.extends(&map),
            "overlapping={overlapping}: fill dropped an assignment"
        );
    }
}

// ---------------------------------------------------------------------------
// Defect 5 — `overlapping` was ignored, so `decode` never matched
// `asmap-tool.py`'s default output.
//
// Golden vector `790100002700c00300ad010002`. Reference output from the
// vendored `asmap.py`.
// ---------------------------------------------------------------------------

#[test]
fn entries_overlapping_is_minimal() {
    let map = load("minimal_vs_flat.bin").expect("valid binary vector");

    // asmap-tool.py's default: overlapping=True.
    let minimal = render(&map.to_entries(false, true));
    assert_eq!(
        minimal,
        vec!["::/2 AS2", "6000::/3 AS2", "8000::/1 AS3", "e000::/3 AS2",],
    );

    // asmap-tool.py -n: overlapping=False. `8000::/1 AS3` splits, because
    // `e000::/3 AS2` sits inside it and may no longer be overridden.
    let flat = render(&map.to_entries(false, false));
    assert_eq!(
        flat,
        vec![
            "::/2 AS2",
            "6000::/3 AS2",
            "8000::/2 AS3",
            "c000::/3 AS3",
            "e000::/3 AS2",
        ],
    );

    assert_ne!(minimal, flat, "the overlapping flag must change the output");
    assert!(
        minimal.len() < flat.len(),
        "the overlapping form exists to be shorter"
    );
}

#[test]
fn overlapping_entries_are_applied_shortest_prefix_first() {
    // The minimal form is only correct for a consumer that lets longer prefixes
    // win, which is what `update_multi` guarantees.
    let map = load("minimal_vs_flat.bin").expect("valid binary vector");
    for overlapping in [false, true] {
        let mut rebuilt = ASMap::new();
        rebuilt.update_multi(map.to_entries(false, overlapping));
        assert_eq!(
            rebuilt, map,
            "overlapping={overlapping}: lossless entries did not round-trip"
        );
    }
}
