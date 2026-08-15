//! Adversarial suite: the attacks that were tried against the ingest path, and
//! what each one does today.
//!
//! Provenance: this file began as `tests/bypass_hunt.rs`, written during review
//! as a *demonstration* suite in which every passing test was a defect. That
//! polarity is unusable in CI — a green run read as an all-clear when it meant
//! the opposite — so each test has been rewritten to assert the behaviour that
//! is actually wanted, and the attacks that are still open are labelled
//! `known_open_*` and pinned to today's behaviour rather than dressed up as
//! passes.
//!
//! Four sections:
//!
//!   1. Attacks the entry gates now reject, each paired with the honest input
//!      that must keep working, so a fix cannot be "reject more".
//!   2. Attacks the epoch bounds now reject.
//!   3. Growth bounds that hold, verified by counting rather than asserted, so
//!      that the absence of a finding is itself evidence.
//!   4. `known_open_*` — attacks that still succeed. These are consensus-policy
//!      questions (who may advance an epoch), not input-validation ones, and
//!      `docs/CLAIM-VALIDATION.md` §8 records them as out of scope for this PR.
//!      They assert *current* behaviour so that changing it is a deliberate act
//!      with a failing test attached, not a silent drift.

use asmap_codec::{ASMap, ip_to_bits};
use bitcoin_asmap_quorum::{
    AsmapClaim, ClaimLimits, EPOCH_ABSOLUTE_MAX, MAX_EPOCH_SKEW, QuorumEngine,
};
use std::net::IpAddr;

#[path = "support/claims.rs"]
mod claims;

use claims::{LOCAL, TOPIC, claim, claim_from_new_peer, entry, settled_default};

/// Resolves one address through a finalized consensus map.
fn lookup(map: &ASMap, addr: &str) -> Option<u32> {
    let ip: IpAddr = addr.parse().unwrap();
    let width = if ip.is_ipv4() { 32 } else { 128 };
    map.lookup(&ip_to_bits(ip, width))
}

/// Feeds one single-entry claim from a fresh identity to a threshold-1 engine
/// and returns the rejection reason, or `None` if it was accepted.
fn reason_for(prefix: &str) -> Option<String> {
    let mut engine = QuorumEngine::with_limits(1, 7, ClaimLimits::default());
    let (peer, c) = claim_from_new_peer(7, vec![entry(prefix, 666)]);
    let accepted = engine.process_claim_from_peer(c, &peer);
    let artifact = engine.finalize(TOPIC, LOCAL);
    if accepted {
        assert!(
            artifact.rejected_claims.is_empty(),
            "{prefix} was accepted but something was rejected: {:?}",
            artifact.rejected_claims
        );
        return None;
    }
    assert_eq!(
        artifact.rejected_claims.len(),
        1,
        "{prefix} must be rejected for exactly one reason: {:?}",
        artifact.rejected_claims
    );
    Some(artifact.rejected_claims.keys().next().unwrap().clone())
}

// ===========================================================================
// 1 — entry-range takeovers
// ===========================================================================

/// A `/0` in *either* family is that family in one entry, and both are rejected.
///
/// The IPv4 half is the one that used to get through. It was justified in
/// source as "IPv4 `/0` is harmless: `ip_to_bits` still emits the 96 bits of the
/// mapped range" — correct about the trie root, wrong about the consequence,
/// because those 96 bits *are* every IPv4 address there is. A two-sender replay
/// at `--threshold 2` was accepted with an empty rejection ledger and `decode`
/// of the artifact printed exactly `0.0.0.0/0 AS666`.
#[test]
fn a_default_route_is_rejected_in_both_families() {
    assert_eq!(
        reason_for("0.0.0.0/0").as_deref(),
        Some("default_route_prefix")
    );
    assert_eq!(reason_for("::/0").as_deref(), Some("default_route_prefix"));
}

/// IPv6 text may not reach the IPv4-mapped range from *below* it — the original
/// rule, kept — nor from *above* it, which is new.
///
/// From below (`::ffff:1.2.3.0/120`) the harm is aliasing: a byte-identical trie
/// path to `1.2.3.0/24` under a different canonical string, so one sender votes
/// a network twice and `finalize` output depends on `HashMap` iteration order.
/// From above the harm is coverage: `::/1` and `::ffff:0:0/95` — the latter host
/// masks to `::fffe:0:0/95`, whose `to_ipv4_mapped()` is `None` — sit at trie
/// nodes strictly shallower than any dotted quad can express, so they reassign
/// IPv4 wholesale using IPv6 syntax. Both used to be accepted.
#[test]
fn ipv6_text_may_not_touch_the_ipv4_mapped_range_from_either_side() {
    for prefix in [
        // below, and at, the mapped range
        "::ffff:1.2.3.0/120",
        "::ffff:0:0/96",
        // above it: every all-zero path is a prefix of `::ffff:0:0/96`
        "::/1",
        "::/64",
        "::/80",
        "::ffff:0:0/95",
    ] {
        assert_eq!(
            reason_for(prefix).as_deref(),
            Some("ipv4_mapped_prefix"),
            "{prefix} covers or aliases the IPv4-mapped range"
        );
    }
}

/// The gates reject a *range*, not a prefix length — and this test is the reason
/// they cannot be turned into a minimum-specificity rule.
///
/// Every prefix here occurs in real Bitcoin Core asmap data. Across the 29
/// snapshots in `data/`, the flat non-overlapping form that `asmap_to_claim`
/// actually emits bottoms out at `224.0.0.0/3` and `1000::/4`, and the
/// overlapping text form of `data/latest_asmap.dat` opens with `::/2` and
/// `0.0.0.0/3`. A rule strict enough to stop `::/1` would reject the shipped
/// map. `8000::/1` is one bit from `::/1` and is accepted for exactly that
/// reason: nothing distinguishes it from `224.0.0.0/3` except which half of the
/// space it names, and it cannot reach IPv4 at all.
#[test]
fn the_shortest_prefixes_real_snapshots_contain_are_still_accepted() {
    for prefix in [
        "224.0.0.0/3",
        "0.0.0.0/3",
        "0.0.0.0/8",
        "1000::/4",
        "800::/5",
        "2000::/6",
        "8000::/1",
    ] {
        assert_eq!(
            reason_for(prefix),
            None,
            "{prefix} occurs in real snapshots and must stay acceptable"
        );
    }
}

/// A broad prefix that *is* accepted does not overwrite more specific ones: the
/// trie keeps the deeper leaf. Recorded because the review reproduction that
/// showed "every IPv4 address now resolves to AS666" used a one-entry map, and
/// the takeover framing only holds for the residual space a real map leaves
/// uncovered — which is still worth rejecting, but is not the whole internet.
#[test]
fn a_broad_prefix_does_not_displace_a_more_specific_one() {
    let mut engine = QuorumEngine::with_limits(1, 7, ClaimLimits::default());
    let (peer, c) = claim_from_new_peer(
        7,
        vec![entry("8000::/1", 666), entry("8000:db8::/32", 15169)],
    );
    assert!(engine.process_claim_from_peer(c, &peer));
    let artifact = engine.finalize(TOPIC, LOCAL);
    assert_eq!(lookup(&artifact.map, "8000:db8::1"), Some(15169));
    assert_eq!(lookup(&artifact.map, "9000::1"), Some(666));
}

// ===========================================================================
// 2 — epoch bounds
// ===========================================================================

/// `QuorumEngine::with_limits` may widen the epoch ceiling to accommodate the
/// epoch it is started at, but never past [`EPOCH_ABSOLUTE_MAX`].
///
/// Unbounded widening is what made Gate 1 unfirable on `replay` without
/// `--epoch`: the starting epoch was read from `claims[0].epoch`, so attacker
/// JSON set both the epoch *and* the ceiling that was supposed to bound it.
#[test]
fn the_starting_epoch_cannot_widen_the_ceiling_past_the_absolute_maximum() {
    let engine = QuorumEngine::with_limits(1, u64::MAX, ClaimLimits::default());
    assert_eq!(engine.limits().max_epoch, EPOCH_ABSOLUTE_MAX);

    // A claim above the absolute ceiling is now rejected by Gate 1 even when the
    // engine was started at an absurd epoch.
    let mut engine = QuorumEngine::with_limits(1, 7, ClaimLimits::default());
    let (peer, c) = claim_from_new_peer(u64::MAX, vec![entry("1.2.3.0/24", 42)]);
    assert!(!engine.process_claim_from_peer(c, &peer));
    assert_eq!(
        engine.finalize(TOPIC, LOCAL).rejected_claims["epoch_out_of_range"],
        1
    );
    assert_eq!(engine.epoch(), 7, "a rejected claim moved the epoch");
}

/// The ceiling is not a ratchet, including under *composition* with the local
/// timer — which is how it became one.
///
/// `serve`/`collect` call `advance_epoch(engine.epoch() + 1)` each tick, and
/// `engine.epoch()` is claim-influenced, so an uncapped `advance_epoch` let one
/// attacker claim per tick lift the ceiling by `MAX_EPOCH_SKEW` per tick without
/// bound. This models six weeks of `serve --epoch 1` at the default 60s tick
/// under one attacker claim per minute; the ceiling must land exactly on the
/// absolute maximum and stop.
#[test]
fn the_serve_timer_cannot_ratchet_the_ceiling_past_the_absolute_maximum() {
    let now = 1_772_726_400u64;
    let mut engine = QuorumEngine::with_limits(2, 1, ClaimLimits::at_unix_time(now));
    assert_eq!(engine.limits().max_epoch, now + MAX_EPOCH_SKEW);

    let attacker = libp2p::PeerId::random();
    for _ in 0..60_000 {
        let next = engine.epoch().saturating_add(MAX_EPOCH_SKEW);
        if next <= engine.limits().max_epoch {
            let c = claim(next, &attacker.to_string(), vec![entry("1.2.3.0/24", 42)]);
            engine.process_claim_from_peer(c, &attacker);
            assert_eq!(engine.epoch(), next);
        }
        // One honest local timer tick, exactly as `run_serve_async` does it.
        let tick = engine.epoch().saturating_add(1);
        engine.advance_epoch(tick);
    }

    assert_eq!(
        engine.limits().max_epoch,
        EPOCH_ABSOLUTE_MAX,
        "the ceiling must saturate at the absolute maximum, not climb past it"
    );
}

/// `advance_epoch` is the *local* path and may raise the ceiling — that is what
/// keeps a long-lived counter-mode node able to accept claims — but the raise is
/// capped, and it may never lower a bound a caller already asked for.
#[test]
fn advance_epoch_raises_the_ceiling_but_only_within_the_absolute_maximum() {
    let mut engine = QuorumEngine::with_limits(1, 7, ClaimLimits::at_unix_time(1_772_726_400));
    let ceiling = engine.limits().max_epoch;
    engine.advance_epoch(ceiling + 1);
    assert_eq!(engine.limits().max_epoch, ceiling + 1 + MAX_EPOCH_SKEW);

    engine.advance_epoch(u64::MAX);
    assert_eq!(engine.limits().max_epoch, EPOCH_ABSOLUTE_MAX);

    // A ceiling deliberately set above the absolute maximum is preserved: the
    // cap bounds the widening, it does not overrule the caller.
    let limits = ClaimLimits {
        max_epoch: EPOCH_ABSOLUTE_MAX + 5_000,
        ..ClaimLimits::default()
    };
    let mut engine = QuorumEngine::with_limits(1, 7, limits);
    assert_eq!(engine.limits().max_epoch, EPOCH_ABSOLUTE_MAX + 5_000);
    engine.advance_epoch(9);
    assert_eq!(engine.limits().max_epoch, EPOCH_ABSOLUTE_MAX + 5_000);
}

/// The §4.3 invariant — a rejected claim never mutates `epoch`, `seen_senders`
/// or `votes` — holds unconditionally, including at `max_senders == 0`.
///
/// It did not. `with_limits` widened with `max_senders.max(threshold)` and
/// `threshold` may be 0, so Gate 8's cap branch saw `0 >= 0` on the set Gate 7
/// had just cleared and rejected a claim that had already moved the epoch. The
/// widening now has a floor of one.
#[test]
fn a_rejected_claim_cannot_advance_the_epoch_even_at_max_senders_zero() {
    let limits = ClaimLimits {
        max_senders: 0,
        ..ClaimLimits::default()
    };
    let mut engine = QuorumEngine::with_limits(0, 5, limits);
    assert_eq!(engine.limits().max_senders, 1);

    let (peer, c) = claim_from_new_peer(6, vec![entry("1.2.3.0/24", 42)]);
    assert!(
        engine.process_claim_from_peer(c, &peer),
        "a fully valid claim must not be rejected by a degenerate sender cap"
    );
    let artifact = engine.finalize(TOPIC, LOCAL);
    assert!(artifact.rejected_claims.is_empty());
    assert_eq!(engine.epoch(), 6);
}

// ===========================================================================
// 3 — growth bounds that hold, verified by counting
// ===========================================================================

/// A flood of authenticated, hash-broken claims is bounded in both the retained
/// observation log and the reason-key set. Recorded so the negative result is
/// evidence rather than assertion.
#[test]
fn flood_of_rejections_is_bounded_in_observations_and_reason_keys() {
    let peer = libp2p::PeerId::random();
    let mut engine = QuorumEngine::with_limits(2, 7, ClaimLimits::default());
    for i in 0..50_000u32 {
        let mut c = claim(7, &peer.to_string(), vec![entry("1.2.3.0/24", i + 1)]);
        c.claim_hash = format!("{i:064x}");
        assert!(!engine.process_claim_from_peer(c, &peer));
    }
    let artifact = engine.finalize(TOPIC, LOCAL);
    assert_eq!(artifact.observations.len(), 1_024);
    assert_eq!(artifact.rejected_claims.len(), 1);
    assert_eq!(artifact.rejected_claims["claim_hash_mismatch"], 50_000);
    assert!(artifact.entries.is_empty());
}

/// Distinct senders are capped, and the observation log with them.
#[test]
fn flood_of_distinct_senders_is_capped_at_max_senders() {
    let mut engine = QuorumEngine::with_limits(2, 7, ClaimLimits::default());
    let mut accepted = 0usize;
    for _ in 0..1_100 {
        let (peer, c) = claim_from_new_peer(7, vec![entry("1.2.3.0/24", 42)]);
        if engine_accepts(&mut engine, c, &peer) {
            accepted += 1;
        }
    }
    let artifact = engine.finalize(TOPIC, LOCAL);
    assert_eq!(artifact.participants.len(), 1_024);
    assert_eq!(artifact.accepted_claims, 1_024);
    assert_eq!(artifact.rejected_claims["sender_limit_exceeded"], 76);
    assert!(accepted > 0);
}

fn engine_accepts(engine: &mut QuorumEngine, c: AsmapClaim, peer: &libp2p::PeerId) -> bool {
    let before = engine.finalize(TOPIC, LOCAL).accepted_claims;
    engine.process_claim_from_peer(c, peer);
    engine.finalize(TOPIC, LOCAL).accepted_claims > before
}

// ===========================================================================
// 4 — KNOWN OPEN: epoch advancement is unauthenticated
// ===========================================================================
//
// Both tests below describe attacks that still work. They are consensus policy,
// not input validation: closing them means deciding *who* may advance an epoch
// (`docs/CLAIM-VALIDATION.md` §4.4 sketches a K-distinct-senders rule), which
// changes what `finalize` emits for well-formed input and is therefore out of
// scope here. §8 records them. They are pinned so the day the policy changes,
// these fail and say so.

/// KNOWN OPEN. One identity may walk the engine's epoch forward one
/// `MAX_EPOCH_SKEW` at a time, because Gate 7's `reset_for_epoch` clears
/// `seen_senders` before Gate 8's dedupe can see the repeat. Nothing rate-limits
/// advancement per identity.
///
/// What this PR fixed is only the *bound*: the walk now terminates at
/// [`EPOCH_ABSOLUTE_MAX`] instead of continuing indefinitely, and it costs
/// ~47k claims rather than one packet. It is still a denial of service.
#[test]
fn known_open_one_identity_can_walk_the_epoch_to_the_absolute_ceiling() {
    let s = settled_default();
    let mut engine = s.engine;
    let start = engine.epoch();
    assert_eq!(engine.finalize(TOPIC, LOCAL).accepted_claims, 2);

    let attacker = libp2p::PeerId::random();
    let mut steps = 0usize;
    while engine.epoch() < EPOCH_ABSOLUTE_MAX {
        let next = engine
            .epoch()
            .saturating_add(MAX_EPOCH_SKEW)
            .min(EPOCH_ABSOLUTE_MAX);
        let c = claim(next, &attacker.to_string(), vec![entry("1.2.3.0/24", 42)]);
        engine.process_claim_from_peer(c, &attacker);
        assert_eq!(engine.epoch(), next, "step {steps} to epoch {next}");
        steps += 1;
    }

    // The walk terminates: the ceiling is real, and it is not lifted by the walk.
    assert_eq!(engine.epoch(), EPOCH_ABSOLUTE_MAX);
    assert_eq!(engine.limits().max_epoch, EPOCH_ABSOLUTE_MAX);
    assert!(
        (40_000..50_000).contains(&steps),
        "cost of the walk from epoch {start} changed: {steps} claims"
    );

    // And the honest round is gone, which is the damage that remains open.
    let (peer, honest) = claim_from_new_peer(start, vec![entry("10.0.0.0/8", 100)]);
    assert!(!engine.process_claim_from_peer(honest, &peer));
    let artifact = engine.finalize(TOPIC, LOCAL);
    assert_eq!(artifact.rejected_claims["stale_epoch"], 1);
    assert!(artifact.entries.is_empty());
}

/// KNOWN OPEN, and the cheaper form: `+1` per claim from a single identity wipes
/// the accumulated round every time. Every one of these claims is *accepted*, so
/// the "a rejected claim never mutates state" invariant does not constrain it —
/// which is precisely why the invariant is not a sufficient answer here.
#[test]
fn known_open_one_identity_can_reset_the_tally_every_round() {
    let s = settled_default();
    let mut engine = s.engine;
    assert_eq!(engine.finalize(TOPIC, LOCAL).entries.len(), 1);

    let attacker = libp2p::PeerId::random();
    for _ in 0..1_000 {
        let next = engine.epoch() + 1;
        let c = claim(next, &attacker.to_string(), vec![entry("1.2.3.0/24", 42)]);
        engine.process_claim_from_peer(c, &attacker);
        assert_eq!(engine.epoch(), next);

        let (peer, honest) = claim_from_new_peer(next - 1, vec![entry("10.0.0.0/8", 100)]);
        assert!(!engine.process_claim_from_peer(honest, &peer));
    }

    let artifact = engine.finalize(TOPIC, LOCAL);
    assert_eq!(
        artifact.accepted_claims, 1,
        "only the attacker's last claim survives; threshold 2 is never reached"
    );
    assert!(
        artifact.entries.is_empty(),
        "consensus is permanently empty"
    );
}
