//! Regression tests for the five codec defects fixed against
//! `contrib/asmap/asmap.py` / `asmap-tool.py`.
//!
//! Reference values in the `to_entries` tests were taken by running the
//! vendored Python on the same inputs.

use std::io::Cursor;

use asmap_codec::{ASMap, ASNEntry, LoadError, ip_to_bits, load_file, parse_network_prefix};

fn entries(pairs: &[(&str, u32)]) -> Vec<ASNEntry> {
    pairs
        .iter()
        .map(|(net, asn)| {
            let (ip, len) = parse_network_prefix(net).expect("canonical prefix");
            (ip_to_bits(ip, len), *asn)
        })
        .collect()
}

/// The worked example from the defect report: Python yields 4 overlapping
/// entries versus 18 flat ones.
fn sample_map() -> ASMap {
    let mut map = ASMap::new();
    map.update_multi(entries(&[
        ("0.0.0.0/0", 1),
        ("1.0.0.0/8", 2),
        ("1.2.0.0/16", 1),
        ("2.0.0.0/8", 3),
    ]));
    map
}

fn load(bytes: &[u8]) -> Result<ASMap, LoadError> {
    load_file(Box::new(Cursor::new(bytes.to_vec())), "test-input")
}

// ---------------------------------------------------------------------------
// F2 — `overlapping` is honoured
// ---------------------------------------------------------------------------

#[test]
fn overlapping_entries_are_minimal() {
    let map = sample_map();
    // Matches contrib/asmap: overlapping=True -> 4, overlapping=False -> 18.
    assert_eq!(map.to_entries(false, true).len(), 4);
    assert_eq!(map.to_entries(false, false).len(), 18);
}

#[test]
fn overlapping_entries_round_trip() {
    for overlapping in [false, true] {
        let map = sample_map();
        let mut rebuilt = ASMap::new();
        // Correctness depends on `update_multi` applying shortest-prefix-first.
        rebuilt.update_multi(map.to_entries(false, overlapping));
        assert_eq!(rebuilt, map, "overlapping={overlapping}");
    }
}

#[test]
fn update_multi_is_shortest_prefix_first() {
    // The overlapping output is only meaningful if longer prefixes win, and it
    // must hold even when the entries arrive longest-first.
    let mut map = ASMap::new();
    let mut reversed = entries(&[("0.0.0.0/0", 1), ("1.0.0.0/8", 2), ("1.2.0.0/16", 3)]);
    reversed.reverse();
    map.update_multi(reversed);
    let (ip, len) = parse_network_prefix("1.2.3.4/32").unwrap();
    assert_eq!(map.lookup(&ip_to_bits(ip, len)), Some(3));
    let (ip, len) = parse_network_prefix("1.3.0.0/16").unwrap();
    assert_eq!(map.lookup(&ip_to_bits(ip, len)), Some(2));
}

// ---------------------------------------------------------------------------
// F3 — `fill` on the flat path
// ---------------------------------------------------------------------------

#[test]
fn fill_absorbs_unassigned_space_and_extends() {
    // 10.0.0.0/8 and 10.2.0.0/16 both AS5, with a hole between them: without
    // fill the flat output must keep them apart; with fill they collapse.
    let mut map = ASMap::new();
    map.update_multi(entries(&[("10.0.0.0/9", 5), ("10.192.0.0/10", 5)]));

    let plain = map.to_entries(false, false);
    let filled = map.to_entries(true, false);
    assert!(
        filled.len() < plain.len(),
        "fill should shorten the list: {} vs {}",
        filled.len(),
        plain.len()
    );

    // fill is lossy: it only guarantees `extends`, never equality.
    let mut rebuilt = ASMap::new();
    rebuilt.update_multi(filled);
    assert!(rebuilt.extends(&map));
    assert_ne!(rebuilt, map);
}

#[test]
fn as0_is_never_emitted() {
    let mut map = ASMap::new();
    map.update_multi(entries(&[("10.0.0.0/8", 5)]));
    for fill in [false, true] {
        for overlapping in [false, true] {
            assert!(
                map.to_entries(fill, overlapping)
                    .iter()
                    .all(|(_, a)| *a > 0),
                "fill={fill} overlapping={overlapping}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// F4 — strict, canonical network prefixes
// ---------------------------------------------------------------------------

#[test]
fn host_bits_are_rejected() {
    for bad in [
        "1.2.3.4/8",
        "1.2.3.4/24",
        "10.0.0.1/8",
        "2001:db8::1/32",
        "1.0.0.0/0",
    ] {
        let err = parse_network_prefix(bad).expect_err(bad);
        assert_eq!(err.to_string(), format!("invalid network '{bad}'"));
    }
}

#[test]
fn canonical_prefixes_are_accepted() {
    for good in [
        "0.0.0.0/0",
        "1.2.3.0/24",
        "1.2.3.4/32",
        "10.0.0.0/8",
        "::/0",
        "2001:db8::/32",
        "::1/128",
    ] {
        parse_network_prefix(good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
}

#[test]
fn out_of_range_prefix_len_is_rejected() {
    for bad in ["1.2.3.0/33", "::/129"] {
        assert!(parse_network_prefix(bad).is_err(), "{bad}");
    }
}

// ---------------------------------------------------------------------------
// F1 / F5 — load_file interpretation matrix
// ---------------------------------------------------------------------------

#[test]
fn text_parse_error_does_not_yield_an_empty_map() {
    // Previously this produced Some(vec![]) -> an empty map with exit 0.
    let err = load(b"1.2.3.0/24 AS7\nthis is garbage\n").expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains("is neither a valid binary asmap file nor valid text input"));
    assert!(msg.contains("unparseable line 'this is garbage'"), "{msg}");
}

#[test]
fn text_parse_errors_report_the_python_wording() {
    let cases: [(&[u8], &str); 3] = [
        (b"1.2.3.0/24 ASxyz\n", "invalid ASN 'ASxyz'"),
        (b"notanip/24 AS7\n", "invalid network 'notanip/24'"),
        // F4's new strictness must surface as a SOFT text error, not an abort.
        (b"1.2.3.4/8 AS7\n", "invalid network '1.2.3.4/8'"),
    ];
    for (input, expected) in cases {
        let msg = load(input).expect_err("must fail").to_string();
        assert!(msg.contains(expected), "expected {expected:?} in {msg:?}");
    }
}

#[test]
fn valid_utf8_binary_input_loads_as_binary() {
    // A binary asmap whose bytes are valid UTF-8 must fall through to the
    // binary interpretation rather than dying with "is ambiguous".
    //
    // `030000` is the contrib/asmap encoding of `::/1 -> AS1`; all three bytes
    // are ASCII control characters, so the file is valid UTF-8 while its single
    // line is unparseable as `NETWORK ASN` text.
    let binary: &[u8] = &[0x03, 0x00, 0x00];
    assert!(std::str::from_utf8(binary).is_ok());

    let mut source = ASMap::new();
    source.update_multi(entries(&[("::/1", 1)]));
    assert_eq!(source.to_binary(false), binary, "fixture drifted");

    let loaded = load(binary).expect("should load as binary, not 'is ambiguous'");
    assert_eq!(loaded, source);
}

#[test]
fn empty_input_is_the_empty_map() {
    // 0 bytes is both valid empty text and a valid empty binary asmap; the
    // ambiguity guard deliberately excludes it.
    assert_eq!(load(b"").expect("empty input is valid"), ASMap::new());
}

#[test]
fn whitespace_and_comments_only_is_the_empty_map() {
    let map = load(b"# comment\n\n   \n").expect("comments are valid text");
    assert_eq!(map, ASMap::new());
}

#[test]
fn invalid_utf8_and_invalid_binary_is_unrecognized() {
    let msg = load(&[0xff, 0xfe, 0xff, 0xfe])
        .expect_err("must fail")
        .to_string();
    assert!(msg.contains("invalid UTF-8"), "{msg}");
}

#[test]
fn text_input_round_trips() {
    let map = load(b"1.2.3.0/24 AS7\n8.0.0.0/8 AS9\n").expect("valid text");
    let mut expected = ASMap::new();
    expected.update_multi(entries(&[("1.2.3.0/24", 7), ("8.0.0.0/8", 9)]));
    assert_eq!(map, expected);
}
