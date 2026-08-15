//! Property tests over randomly generated ASMaps.
//!
//! Pure Rust: no Python, no extra dependency, part of the default `cargo test`
//! run. The oracle-parity counterpart lives in
//! `crates/bitcoin-asmap-quorum/tests/differential_python.rs`.
//!
//! Every test is seeded from `ASMAP_TEST_SEED` (default 1234, the value the
//! original 0/81 measurement used) and reports the failing trial's seed, which
//! is all the reproduction anyone needs.

use asmap_codec::testgen::{RandomMapParams, SplitMix64, random_map, splitmix64};
use asmap_codec::{ASMap, ASNEntry};

/// Master seed. Overridable so a nightly job can sweep a different corpus.
fn master_seed() -> u64 {
    std::env::var("ASMAP_TEST_SEED")
        .ok()
        .map(|v| v.parse().expect("ASMAP_TEST_SEED must be a u64"))
        .unwrap_or(1234)
}

/// Number of random maps per property. `ASMAP_TEST_TRIALS` widens the sweep.
fn trials() -> u64 {
    std::env::var("ASMAP_TEST_TRIALS")
        .ok()
        .map(|v| v.parse().expect("ASMAP_TEST_TRIALS must be a u64"))
        .unwrap_or(1000)
}

/// Trial `t` is a pure function of `splitmix64(master ^ t)` — independent of
/// how many trials ran before it, so `ASMAP_TEST_TRIALS` never shifts the
/// corpus, it only extends it.
fn trial_seed(t: u64) -> u64 {
    splitmix64(master_seed() ^ t)
}

fn each_trial(mut body: impl FnMut(u64, &ASMap, RandomMapParams)) {
    for t in 0..trials() {
        let seed = trial_seed(t);
        let mut rng = SplitMix64::new(seed);
        let params = RandomMapParams::draw(&mut rng);
        let map = random_map(&mut rng, params);
        body(seed, &map, params);
    }
}

fn rebuild(entries: Vec<ASNEntry>) -> ASMap {
    let mut map = ASMap::new();
    map.update_multi(entries);
    map
}

#[test]
fn binary_roundtrip_empty() {
    let state = ASMap::new();
    let enc = state.to_binary(false);
    assert!(enc.is_empty(), "the empty map encodes to zero bytes");
    let dec = ASMap::from_binary(&enc).expect("empty input decodes");
    assert_eq!(state, dec);
}

/// `from_binary(to_binary(m)) == m` — the headline round-trip.
///
/// With `fill`, encoding is lossy by design (it may claim unassigned ranges to
/// shrink the output), so the requirement weakens to `decoded.extends(m)`, plus
/// the decoded map being a fixed point of a further lossless round-trip.
#[test]
fn binary_roundtrip_random_maps() {
    each_trial(|seed, map, params| {
        let lossless = map.to_binary(false);
        let decoded = ASMap::from_binary(&lossless)
            .unwrap_or_else(|| panic!("seed {seed} {params:?}: to_binary(false) did not decode"));
        assert_eq!(
            &decoded, map,
            "seed {seed} {params:?}: from_binary(to_binary(false)) != m"
        );

        let filled = map.to_binary(true);
        let decoded = ASMap::from_binary(&filled)
            .unwrap_or_else(|| panic!("seed {seed} {params:?}: to_binary(true) did not decode"));
        assert!(
            decoded.extends(map),
            "seed {seed} {params:?}: filled encoding lost an assignment"
        );
        let refixed = ASMap::from_binary(&decoded.to_binary(false))
            .unwrap_or_else(|| panic!("seed {seed} {params:?}: re-encode did not decode"));
        assert_eq!(
            refixed, decoded,
            "seed {seed} {params:?}: filled decode is not a round-trip fixed point"
        );
    });
}

/// `update_multi(m.to_entries(..)) == m` for all four flag combinations.
///
/// This is the direct property behind the `to_entries` rewrite: the overlapping
/// (minimal) form is only correct if a consumer applying entries
/// shortest-prefix-first reconstructs exactly the source map.
#[test]
fn entries_roundtrip_random_maps() {
    each_trial(|seed, map, params| {
        for overlapping in [false, true] {
            let exact = rebuild(map.to_entries(false, overlapping));
            assert_eq!(
                &exact, map,
                "seed {seed} {params:?}: overlapping={overlapping} fill=false did not round-trip"
            );

            let filled = rebuild(map.to_entries(true, overlapping));
            assert!(
                filled.extends(map),
                "seed {seed} {params:?}: overlapping={overlapping} fill=true lost an assignment"
            );
        }
    });
}

/// The minimal (overlapping) form must never be longer than the flat one, and
/// `fill` must never lengthen either form. A regression that quietly returned
/// the flat list from the overlapping path — the original defect — fails here
/// on the first map where the two differ.
#[test]
fn minimal_entries_are_never_longer_than_flat() {
    let mut strictly_shorter = 0u64;
    each_trial(|seed, map, params| {
        for fill in [false, true] {
            let flat = map.to_entries(fill, false).len();
            let minimal = map.to_entries(fill, true).len();
            assert!(
                minimal <= flat,
                "seed {seed} {params:?}: fill={fill} minimal={minimal} > flat={flat}"
            );
            if minimal < flat {
                strictly_shorter += 1;
            }
        }
        assert!(
            map.to_entries(true, false).len() <= map.to_entries(false, false).len(),
            "seed {seed} {params:?}: fill lengthened the flat form"
        );
        assert!(
            map.to_entries(true, true).len() <= map.to_entries(false, true).len(),
            "seed {seed} {params:?}: fill lengthened the minimal form"
        );
    });
    assert!(
        strictly_shorter > 0,
        "the corpus never exercised the case the overlapping flag exists for"
    );
}

/// `to_binary` must be a pure function of the map's *value*, not of how the
/// map was built or of any hash-map iteration order inside `to_binnode`.
///
/// The review flagged `BTreeSet<Option<u32>>` (which orders `None` first) as a
/// possible divergence from `asmap.py`'s `sorted(union, key=(x is None, x))`
/// (which orders it last). It is not one: that loop writes only `ret[ctx]` on
/// iteration `ctx`, so its result is order-independent. This test pins that,
/// and pins the `HashMap` in `to_binnode` against ever leaking its iteration
/// order into the output.
#[test]
fn binary_encoding_is_deterministic() {
    each_trial(|seed, map, params| {
        for fill in [false, true] {
            let expected = map.to_binary(fill);

            for _ in 0..4 {
                assert_eq!(
                    map.to_binary(fill),
                    expected,
                    "seed {seed} {params:?}: fill={fill} to_binary is not idempotent"
                );
            }

            // Same value, three different construction paths.
            let via_flat = rebuild(map.to_entries(false, false));
            let via_minimal = rebuild(map.to_entries(false, true));
            let via_binary =
                ASMap::from_binary(&map.to_binary(false)).expect("lossless encoding decodes");
            for (label, other) in [
                ("flat entries", &via_flat),
                ("minimal entries", &via_minimal),
                ("binary", &via_binary),
            ] {
                assert_eq!(
                    other, map,
                    "seed {seed} {params:?}: rebuild via {label} != m"
                );
                assert_eq!(
                    other.to_binary(fill),
                    expected,
                    "seed {seed} {params:?}: fill={fill} encoding depends on construction path ({label})"
                );
            }
        }
    });
}

/// Truncating, extending or perturbing a valid encoding must never panic and
/// must never silently produce a map that re-encodes to the mutated bytes.
#[test]
fn mutated_binary_never_panics() {
    each_trial(|seed, map, params| {
        let base = map.to_binary(false);
        let mut rng = SplitMix64::new(seed ^ 0xA5A5_A5A5_A5A5_A5A5);
        for _ in 0..4 {
            let mut bytes = base.clone();
            match rng.below(4) {
                0 if !bytes.is_empty() => {
                    bytes.truncate(rng.below(bytes.len() as u64) as usize);
                }
                1 if !bytes.is_empty() => {
                    let i = rng.below(bytes.len() as u64) as usize;
                    bytes[i] ^= 1u8 << rng.below(8);
                }
                2 => bytes.push(rng.below(256) as u8),
                _ => bytes.push(0),
            }
            if let Some(decoded) = ASMap::from_binary(&bytes) {
                // Accepting is fine; producing something that does not survive
                // its own round-trip is not.
                let re = decoded.to_binary(false);
                assert_eq!(
                    ASMap::from_binary(&re).as_ref(),
                    Some(&decoded),
                    "seed {seed} {params:?}: mutated input decoded to a non-round-tripping map"
                );
            }
        }
    });
}
