//! SUITE B — what the tally does when honest nodes disagree.
//!
//! Every claim in this file is **valid**. Nothing here is about input
//! validation; SUITE A covers that. These tests pin what `finalize()` emits
//! when well-formed claims say different things, which is the behaviour the
//! `claim-validation` PR must not have changed and which nothing in the
//! repository previously asserted.
//!
//! Pure `QuorumEngine` and `PeerId::random()`. No swarm, no bitcoind, no I/O,
//! no `#[tokio::test]`.
//!
//! # Predictions
//!
//! Each prediction below was written before the test was run, and every one was
//! then run. Where prediction and behaviour differ, the **behaviour** is what
//! the test asserts, with a comment saying it is documented rather than
//! endorsed — a test suite that asserts what the author wished for is worse
//! than no test at all.
//!
//! | # | Case | Predicted | Actual |
//! | --- | --- | --- | --- |
//! | B1 | direct conflict on one prefix | no entry, both claims accepted, quorum still signalled | as predicted |
//! | B2 | a prefix only one node reports | dropped; `lookup` gives `Some(0)`, not `None` | as predicted |
//! | B3 | partial overlap | shared prefixes kept with their true vote counts, the rest dropped | as predicted |
//! | B4 | disjoint shards | **empty consensus map** at threshold 2 and 3, while every claim is accepted | as predicted — see FINDING F0 |
//! | B5 | exactly threshold vs one short | only the exact one survives | as predicted |
//! | B6 | tie above threshold | broken by the lower ASN | as predicted |
//! | B7 | majority beats minority | higher count wins before the ASN tie-break | as predicted |
//! | B8 | same input, reversed order | byte-identical artifact | as predicted |
//! | B9 | quorum of senders vs consensus on a prefix | `true` returned with an empty map | as predicted |
//! | B10 | `threshold = 0` | quorum signalled before any claim; every single vote enters consensus | as predicted — see FINDING F9 |
//! | B11 | nested prefixes | both in the report, most-specific wins in the trie | as predicted |
//! | B12 | one sender repeating itself | dedupes to one vote, cannot reach threshold alone | as predicted |
//!
//! # FINDING F0 — sharding and the tally rule are mutually exclusive
//!
//! `assigned_collectors` gives each node a **strictly disjoint** slice of the
//! collector list (`idx % participants.len() == local_index`), while
//! `finalize` keeps only `(prefix, asn)` pairs carrying `>= threshold`
//! **identical** votes. `collect` defaults to `--threshold 3`. B4 confirms the
//! consequence directly: three nodes with disjoint shards produce
//! `entries == []` and an empty map at threshold 2 or 3, while every claim is
//! accepted and the engine signals that quorum was reached.
//!
//! Sharding wants union semantics; the tally implements intersection
//! semantics. In production the map is non-empty only insofar as different RIS
//! collectors happen to derive the *same* bottleneck ASN for the same prefix.
//!
//! **This is a consensus design decision and is explicitly out of scope for the
//! `claim-validation` PR.** B4 and B9 pin the behaviour as it stands so that
//! nobody changes it by accident; neither test endorses it.
//!
//! # FINDING F9 — `--threshold 0` is accepted
//!
//! `parse_serve_args` / `parse_collect_args` / `parse_replay_args` take the
//! threshold as a bare `usize` with no lower bound. At zero, `*count < 0` is
//! never true, so every single-vote prefix enters consensus, and
//! `seen_senders.len() >= 0` makes the engine signal quorum before a single
//! claim has arrived. B10 pins it. Also out of scope here — the fix is an
//! argument-parsing bound, not a tally change.

use std::net::IpAddr;

use asmap_codec::ip_to_bits;
use bitcoin_asmap_quorum::{ClaimLimits, ConsensusArtifact, QuorumEngine};

#[path = "support/claims.rs"]
mod claims;

use claims::{LOCAL, SETTLED_EPOCH, TOPIC, claim_from_new_peer, entry};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Feeds one claim per element of `bodies`, each from a fresh sender, and
/// returns both the artifact and what each call returned.
fn run_round(threshold: usize, bodies: Vec<Vec<(&str, u32)>>) -> (ConsensusArtifact, Vec<bool>) {
    let mut engine = QuorumEngine::with_limits(threshold, SETTLED_EPOCH, ClaimLimits::default());
    let mut returns = Vec::new();
    for body in bodies {
        let entries = body.into_iter().map(|(p, a)| entry(p, a)).collect();
        let (source, c) = claim_from_new_peer(SETTLED_EPOCH, entries);
        returns.push(engine.process_claim_from_peer(c, &source));
    }
    (engine.finalize(TOPIC, LOCAL), returns)
}

/// `(prefix, asn, votes)` for every consensus entry, in report order.
fn triples(artifact: &ConsensusArtifact) -> Vec<(String, u32, usize)> {
    artifact
        .entries
        .iter()
        .map(|e| (e.ip_prefix.clone(), e.asn, e.votes))
        .collect()
}

/// What the emitted map resolves `prefix` to.
///
/// Returns `Some(0)`, not `None`, for address space the map does not assign:
/// ASN 0 is ASMap's "unassigned" sentinel and is a legal trie value, so a test
/// asserting `None` here would pass for the wrong reason.
fn lookup(artifact: &ConsensusArtifact, prefix: &str) -> Option<u32> {
    let (addr, len) = prefix.split_once('/').expect("prefix needs a length");
    let ip: IpAddr = addr.parse().expect("prefix needs a parsable address");
    artifact.map.lookup(&ip_to_bits(ip, len.parse().unwrap()))
}

fn map_entry_count(artifact: &ConsensusArtifact) -> usize {
    artifact.map.to_entries(false, false).len()
}

// ---------------------------------------------------------------------------
// B1 — direct conflict
// ---------------------------------------------------------------------------

/// **Predicted:** each ASN gets one vote, neither reaches a threshold of two,
/// so the consensus map is empty — while both claims are recorded accepted and
/// the second call still returns `true`, because it is reporting a quorum of
/// *senders*, not agreement on anything.
///
/// **Actual:** as predicted.
#[test]
fn direct_conflict_on_one_prefix_yields_no_consensus_entry() {
    let (artifact, returns) = run_round(2, vec![vec![("1.2.3.0/24", 1)], vec![("1.2.3.0/24", 2)]]);

    assert_eq!(returns, vec![false, true]);
    assert_eq!(artifact.accepted_claims, 2);
    assert_eq!(artifact.participants.len(), 2);
    assert!(artifact.rejected_claims.is_empty());
    assert!(
        artifact.entries.is_empty(),
        "two senders contradicting each other must not produce an entry"
    );
    assert_eq!(map_entry_count(&artifact), 0);
    assert_eq!(lookup(&artifact, "1.2.3.0/24"), Some(0));
}

// ---------------------------------------------------------------------------
// B2 — a prefix only one node reports
// ---------------------------------------------------------------------------

/// **Predicted:** the agreed prefix carries three votes and reaches the map;
/// the prefix only C reports carries one and does not. A lookup of the missing
/// prefix gives `Some(0)` — the unassigned sentinel — not `None`.
///
/// **Actual:** as predicted, including the `Some(0)`.
#[test]
fn a_prefix_only_one_node_reports_never_reaches_the_map() {
    let (artifact, _) = run_round(
        2,
        vec![
            vec![("10.0.0.0/8", 100)],
            vec![("10.0.0.0/8", 100)],
            vec![("10.0.0.0/8", 100), ("192.168.0.0/16", 200)],
        ],
    );

    assert_eq!(triples(&artifact), vec![("10.0.0.0/8".to_string(), 100, 3)]);
    assert_eq!(lookup(&artifact, "10.0.0.0/8"), Some(100));
    assert_eq!(
        lookup(&artifact, "192.168.0.0/16"),
        Some(0),
        "unassigned space reads as ASN 0, never as None"
    );
}

// ---------------------------------------------------------------------------
// B3 — partial overlap
// ---------------------------------------------------------------------------

/// **Predicted:** P1 (all three) and P2 (two of three) survive with their true
/// counts; P3 (one) is dropped. Report order is votes-descending.
///
/// **Actual:** as predicted.
#[test]
fn partial_overlap_keeps_the_shared_prefixes_and_drops_the_rest() {
    let (artifact, _) = run_round(
        2,
        vec![
            vec![("1.0.0.0/8", 1), ("2.0.0.0/8", 2)],
            vec![("1.0.0.0/8", 1), ("3.0.0.0/8", 3)],
            vec![("1.0.0.0/8", 1), ("2.0.0.0/8", 2)],
        ],
    );

    assert_eq!(
        triples(&artifact),
        vec![
            ("1.0.0.0/8".to_string(), 1, 3),
            ("2.0.0.0/8".to_string(), 2, 2),
        ]
    );
    assert_eq!(lookup(&artifact, "3.0.0.0/8"), Some(0));
}

// ---------------------------------------------------------------------------
// B4 — disjoint shards. FINDING F0.
// ---------------------------------------------------------------------------

/// **Predicted:** at threshold 1 all six prefixes reach the map; at threshold 2
/// and 3 the consensus map is **completely empty** even though all three claims
/// are accepted and the engine signals quorum.
///
/// **Actual:** as predicted, at every threshold.
///
/// This is the shape `assigned_collectors` actually produces — it partitions
/// the collector list so that no two nodes fetch the same collector — combined
/// with `collect`'s default `--threshold 3`.
///
/// **Documented, not endorsed.** Sharding wants union semantics and the tally
/// implements intersection semantics; which one is right is a consensus design
/// decision for the maintainer and is out of scope for the validation PR. This
/// test exists so that whichever way it is settled, it is settled deliberately.
#[test]
fn disjoint_shards_produce_an_empty_consensus_map() {
    let shards = || {
        vec![
            vec![("1.0.0.0/8", 1), ("2.0.0.0/8", 2)],
            vec![("3.0.0.0/8", 3), ("4.0.0.0/8", 4)],
            vec![("5.0.0.0/8", 5), ("6.0.0.0/8", 6)],
        ]
    };

    let (at_one, returns) = run_round(1, shards());
    assert_eq!(returns, vec![true, true, true]);
    assert_eq!(at_one.entries.len(), 6, "union semantics at threshold 1");
    assert_eq!(at_one.accepted_claims, 3);

    for threshold in [2, 3] {
        let (artifact, returns) = run_round(threshold, shards());
        assert_eq!(
            artifact.accepted_claims, 3,
            "every claim is accepted at threshold {threshold}"
        );
        assert!(
            artifact.rejected_claims.is_empty(),
            "nothing is rejected at threshold {threshold}"
        );
        assert!(
            *returns.last().unwrap(),
            "the engine signals quorum at threshold {threshold}"
        );
        assert!(
            artifact.entries.is_empty(),
            "threshold {threshold}: sharded nodes share no prefix, so nothing \
             clears the tally"
        );
        assert_eq!(map_entry_count(&artifact), 0);
    }
}

// ---------------------------------------------------------------------------
// B5 — the threshold boundary
// ---------------------------------------------------------------------------

/// **Predicted:** a prefix with exactly `threshold` votes is kept; one with
/// `threshold - 1` is dropped. The comparison is `*count < threshold`, so the
/// boundary is inclusive.
///
/// **Actual:** as predicted.
#[test]
fn exactly_threshold_votes_are_kept_and_threshold_minus_one_is_dropped() {
    let (artifact, _) = run_round(
        3,
        vec![
            vec![("1.0.0.0/8", 1), ("9.0.0.0/8", 9)],
            vec![("1.0.0.0/8", 1), ("9.0.0.0/8", 9)],
            vec![("1.0.0.0/8", 1)],
        ],
    );

    assert_eq!(
        triples(&artifact),
        vec![("1.0.0.0/8".to_string(), 1, 3)],
        "exactly 3 of 3 survives; 2 of 3 does not"
    );
}

// ---------------------------------------------------------------------------
// B6 / B7 — resolving two ASNs that both clear the threshold
// ---------------------------------------------------------------------------

/// **Predicted:** both ASNs clear a threshold of two, and the tie-break
/// `*asn < best.0` picks the lower — AS42 — with two votes and exactly one
/// entry, not two.
///
/// **Actual:** as predicted.
///
/// Worth noting what the rule is *not*: it is arbitrary-but-deterministic, not
/// a correctness argument. Determinism is the property that matters, because
/// independent operators must produce byte-identical artifacts.
#[test]
fn a_tie_above_threshold_is_broken_by_the_lower_asn() {
    let (artifact, _) = run_round(
        2,
        vec![
            vec![("1.2.3.0/24", 777)],
            vec![("1.2.3.0/24", 777)],
            vec![("1.2.3.0/24", 42)],
            vec![("1.2.3.0/24", 42)],
        ],
    );

    assert_eq!(
        triples(&artifact),
        vec![("1.2.3.0/24".to_string(), 42, 2)],
        "one prefix yields one entry, and the tie goes to the lower ASN"
    );
    assert_eq!(lookup(&artifact, "1.2.3.0/24"), Some(42));
}

/// **Predicted:** with 3 votes for AS1 and 2 for AS2, both above a threshold of
/// two, the count comparison runs before the ASN tie-break, so AS1 wins with
/// three votes — the majority, not the numerically smaller ASN.
///
/// **Actual:** as predicted.
#[test]
fn a_majority_above_threshold_beats_a_minority_above_threshold() {
    let (artifact, _) = run_round(
        2,
        vec![
            vec![("1.2.3.0/24", 1)],
            vec![("1.2.3.0/24", 1)],
            vec![("1.2.3.0/24", 1)],
            vec![("1.2.3.0/24", 2)],
            vec![("1.2.3.0/24", 2)],
        ],
    );

    assert_eq!(triples(&artifact), vec![("1.2.3.0/24".to_string(), 1, 3)]);
}

// ---------------------------------------------------------------------------
// B8 — order independence
// ---------------------------------------------------------------------------

/// **Predicted:** identical claims delivered in opposite orders give identical
/// artifacts, including nested prefixes. `best_by_prefix` is a `HashMap`
/// iterated under `RandomState`, but each prefix is a distinct key, the report
/// is sorted before emission, and `update_multi` sorts entries by prefix length
/// — so nesting resolves the same way regardless of arrival order.
///
/// **Actual:** as predicted.
///
/// This is the property the whole attestation workflow rests on: independent
/// operators replaying the same claims must emit the same bytes.
#[test]
fn identical_input_in_a_different_order_yields_an_identical_artifact() {
    let bodies = vec![
        vec![("1.0.0.0/8", 1), ("1.2.3.0/24", 2)],
        vec![("1.0.0.0/8", 1), ("1.2.3.0/24", 2)],
        vec![("1.0.0.0/8", 1), ("4.0.0.0/8", 4)],
    ];
    let mut reversed = bodies.clone();
    reversed.reverse();

    let (first, _) = run_round(2, bodies.clone());

    // Looped deliberately. `best_by_prefix` is a `HashMap` under `RandomState`,
    // freshly seeded per instance, so an order dependency shows up as a *flaky*
    // failure rather than a reliable one — a single comparison would pass most
    // of the time even with the bug present. This is exactly how the
    // IPv4-mapped aliasing defect hid: it produced two different artifacts from
    // one input across ten identical replay runs.
    for round in 0..32 {
        let (forwards, _) = run_round(2, bodies.clone());
        let (backwards, _) = run_round(2, reversed.clone());

        assert_eq!(triples(&forwards), triples(&backwards), "round {round}");
        assert_eq!(
            forwards.map.to_binary(false),
            backwards.map.to_binary(false),
            "round {round}: the emitted map must not depend on arrival order"
        );
        assert_eq!(
            first.map.to_binary(false),
            forwards.map.to_binary(false),
            "round {round}: the emitted map must not depend on the run either"
        );

        // And the nesting really is nested, so the checks above are not vacuous.
        assert_eq!(lookup(&forwards, "1.2.3.0/24"), Some(2));
        assert_eq!(lookup(&forwards, "1.9.0.0/16"), Some(1));
    }
}

// ---------------------------------------------------------------------------
// B9 — the semantic gap, named
// ---------------------------------------------------------------------------

/// **Predicted:** `process_claim_from_peer` returns `true` — its return value
/// is `seen_senders.len() >= threshold`, a count of *participants* — at the
/// same moment `finalize()` produces nothing at all.
///
/// **Actual:** as predicted.
///
/// Named explicitly so that nobody "fixes" one of the two meanings by accident.
/// A caller reading the boolean as "consensus reached" is reading it wrong, and
/// `serve`/`collect` both use it to decide when to write an artifact — which is
/// how an empty map gets written and attested.
#[test]
fn a_quorum_of_senders_is_not_a_consensus_on_any_prefix() {
    let mut engine = QuorumEngine::with_limits(2, SETTLED_EPOCH, ClaimLimits::default());

    let (source_a, a) = claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 1)]);
    let (source_b, b) = claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 2)]);

    assert!(!engine.process_claim_from_peer(a, &source_a));
    let quorum_reached = engine.process_claim_from_peer(b, &source_b);

    assert!(quorum_reached, "the threshold counts senders");
    let artifact = engine.finalize(TOPIC, LOCAL);
    assert!(
        artifact.entries.is_empty(),
        "...and says nothing about whether they agreed"
    );
    assert_eq!(map_entry_count(&artifact), 0);
}

// ---------------------------------------------------------------------------
// B10 — threshold zero. FINDING F9.
// ---------------------------------------------------------------------------

/// **Predicted:** `seen_senders.len() >= 0` holds before any claim arrives, so
/// the engine signals quorum with nothing in it; and `*count < 0` is never
/// true, so every single-vote prefix enters consensus unchallenged.
///
/// **Actual:** as predicted.
///
/// **Documented, not endorsed.** `--threshold 0` parses as a bare `usize` at
/// the CLI with no lower bound. The fix is an argument bound, not a tally
/// change, so it is out of scope here — but the behaviour should not be allowed
/// to change silently.
#[test]
fn threshold_zero_accepts_everything_from_nobody() {
    let mut engine = QuorumEngine::with_limits(0, SETTLED_EPOCH, ClaimLimits::default());

    let empty = engine.finalize(TOPIC, LOCAL);
    assert_eq!(empty.accepted_claims, 0);
    assert!(empty.participants.is_empty());

    let (source, c) = claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 64512)]);
    assert!(
        engine.process_claim_from_peer(c, &source),
        "quorum is signalled by the very first claim"
    );

    let artifact = engine.finalize(TOPIC, LOCAL);
    assert_eq!(
        triples(&artifact),
        vec![("1.2.3.0/24".to_string(), 64512, 1)],
        "a single unchallenged vote becomes consensus"
    );
}

// ---------------------------------------------------------------------------
// B11 — nesting
// ---------------------------------------------------------------------------

/// **Predicted:** both prefixes appear in the report with two votes each, and
/// in the trie the more specific one wins for addresses it covers while the
/// covering prefix keeps the rest. The report is a flat list of what was voted;
/// the map is where nesting is resolved.
///
/// **Actual:** as predicted.
#[test]
fn nested_prefixes_from_agreeing_senders_resolve_most_specific_first() {
    let (artifact, _) = run_round(
        2,
        vec![
            vec![("1.0.0.0/8", 1), ("1.2.3.0/24", 2)],
            vec![("1.0.0.0/8", 1), ("1.2.3.0/24", 2)],
        ],
    );

    assert_eq!(artifact.entries.len(), 2);
    assert_eq!(lookup(&artifact, "1.2.3.0/24"), Some(2));
    assert_eq!(lookup(&artifact, "1.2.4.0/24"), Some(1));
    assert_eq!(lookup(&artifact, "1.9.0.0/16"), Some(1));
    assert_eq!(lookup(&artifact, "2.0.0.0/8"), Some(0));
}

// ---------------------------------------------------------------------------
// B12 — self-reinforcement
// ---------------------------------------------------------------------------

/// **Predicted:** a sender repeating one assertion three times casts one vote,
/// so it cannot reach a threshold of two alone; the consensus map stays empty
/// and nothing is rejected.
///
/// **Actual:** as predicted.
///
/// The intra-claim dedupe is keyed on the canonical prefix, so the repeats
/// collapse before the tally sees them. (A repeat that *disagreed* with itself
/// would be rejected outright as `conflicting_entry` — SUITE A covers that.)
#[test]
fn one_sender_repeating_a_prefix_cannot_manufacture_a_quorum() {
    let (artifact, returns) = run_round(
        2,
        vec![vec![
            ("1.2.3.0/24", 1),
            ("1.2.3.0/24", 1),
            ("1.2.3.0/24", 1),
        ]],
    );

    assert_eq!(returns, vec![false]);
    assert_eq!(artifact.accepted_claims, 1);
    assert!(artifact.rejected_claims.is_empty());
    assert!(artifact.entries.is_empty());
    assert_eq!(map_entry_count(&artifact), 0);
}
