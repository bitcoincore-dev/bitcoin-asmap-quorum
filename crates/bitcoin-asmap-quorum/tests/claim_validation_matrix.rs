//! SUITE A — the claim validation matrix.
//!
//! One test per validation rule in `docs/CLAIM-VALIDATION.md` §3. Every one of
//! them asserts the same three things:
//!
//! 1. the claim was **rejected**;
//! 2. under the **named reason**, with no other reason counter moving;
//! 3. and **no shared engine state moved** — not `epoch`, not `participants`,
//!    not `accepted_claims`, not the consensus `entries`, not the `map`.
//!
//! (3) is the point of the suite. The per-reason unit tests in `src/lib.rs`
//! assert (1) and (2), and they pass just as happily with the gates in the
//! wrong order — which is exactly how the pre-`claim-validation` engine let a
//! claim it was about to reject wipe the entire accumulated round first
//! (`docs/CLAIM-VALIDATION.md` §4.2). Only an assertion against a *settled*
//! engine catches that, and these tests are all run against one.
//!
//! These are integration tests on purpose: they see only the public API, the
//! same surface a downstream consumer sees, so nothing here can accidentally
//! reach past the boundary the validation is supposed to defend.
//!
//! ## The mechanism that makes a missing test loud
//!
//! [`Rule`] is a closed enum with no wildcard arm in any of its matches, so
//! adding a variant without a case is a **compile error**. Three meta-tests
//! close the loop on the other direction:
//!
//! - [`every_rule_is_exercised_by_a_named_test`] — a variant in `Rule::ALL`
//!   with no `#[test]` of its own fails.
//! - [`every_reason_in_the_source_has_a_matrix_case`] — a `count_rejection`
//!   added to `src/lib.rs` with no matrix row fails, naming the reason.
//! - [`every_reason_in_the_spec_has_a_matrix_case`] — a row added to §3 of the
//!   specification with no matrix row fails, naming the reason.

use std::collections::BTreeSet;

use bitcoin_asmap_quorum::{
    ASN_MAX, ClaimLimits, MAX_EPOCH_SKEW, MAX_PREFIX_LEN, MAX_SENDER_ID_LEN, QuorumEngine,
};
use libp2p::PeerId;

#[path = "support/claims.rs"]
mod claims;

use claims::{
    LOCAL, Record, SETTLED_EPOCH, Settled, TOPIC, assert_helper_matches_the_engine,
    assert_rejected, claim, claim_from_new_peer, entry, reasons_in_source, reasons_in_spec,
    settled, settled_default, snapshot,
};

// ---------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------

/// Every validation rule that can reject a claim.
///
/// One variant per rejection reason in `docs/CLAIM-VALIDATION.md` §3. The
/// matches below are exhaustive by design — no `_` arm anywhere — so a new rule
/// cannot be added to the library without this file failing to compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    OversizeClaim,
    MalformedClaim,
    InvalidSenderId,
    SourceMismatch,
    MalformedClaimHash,
    ClaimHashMismatch,
    EmptyClaim,
    TooManyEntries,
    EpochOutOfRange,
    StaleEpoch,
    EpochJumpTooLarge,
    AsnOutOfRange,
    UnassignedAsn,
    InvalidPrefix,
    Ipv4MappedPrefix,
    DefaultRoutePrefix,
    ConflictingEntry,
    SenderLimitExceeded,
    DuplicateSender,
    UnparsableSender,
}

impl Rule {
    const ALL: &'static [Rule] = &[
        Rule::OversizeClaim,
        Rule::MalformedClaim,
        Rule::InvalidSenderId,
        Rule::SourceMismatch,
        Rule::MalformedClaimHash,
        Rule::ClaimHashMismatch,
        Rule::EmptyClaim,
        Rule::TooManyEntries,
        Rule::EpochOutOfRange,
        Rule::StaleEpoch,
        Rule::EpochJumpTooLarge,
        Rule::AsnOutOfRange,
        Rule::UnassignedAsn,
        Rule::InvalidPrefix,
        Rule::Ipv4MappedPrefix,
        Rule::DefaultRoutePrefix,
        Rule::ConflictingEntry,
        Rule::SenderLimitExceeded,
        Rule::DuplicateSender,
        Rule::UnparsableSender,
    ];

    /// The reason string the report must carry. Exhaustive, no wildcard.
    fn reason(self) -> &'static str {
        match self {
            Rule::OversizeClaim => "oversize_claim",
            Rule::MalformedClaim => "malformed_claim",
            Rule::InvalidSenderId => "invalid_sender_id",
            Rule::SourceMismatch => "source_mismatch",
            Rule::MalformedClaimHash => "malformed_claim_hash",
            Rule::ClaimHashMismatch => "claim_hash_mismatch",
            Rule::EmptyClaim => "empty_claim",
            Rule::TooManyEntries => "too_many_entries",
            Rule::EpochOutOfRange => "epoch_out_of_range",
            Rule::StaleEpoch => "stale_epoch",
            Rule::EpochJumpTooLarge => "epoch_jump_too_large",
            Rule::AsnOutOfRange => "asn_out_of_range",
            Rule::UnassignedAsn => "unassigned_asn",
            Rule::InvalidPrefix => "invalid_prefix",
            Rule::Ipv4MappedPrefix => "ipv4_mapped_prefix",
            Rule::DefaultRoutePrefix => "default_route_prefix",
            Rule::ConflictingEntry => "conflicting_entry",
            Rule::SenderLimitExceeded => "sender_limit_exceeded",
            Rule::DuplicateSender => "duplicate_sender",
            Rule::UnparsableSender => "unparsable_sender",
        }
    }

    /// Whether the rejection leaves a row in `observations`.
    ///
    /// Every pre-authentication rejection is deliberately counter-only: a
    /// `ClaimObservation` retains the sender's own string, so retaining one for
    /// input that has not yet proved *who* it is would reopen the
    /// unbounded-growth vector the gate reorder closed. Exhaustive, no
    /// wildcard — a new rule must state its retention policy.
    fn record(self) -> Record {
        match self {
            // Envelope counters: there is no claim to observe, only bytes that
            // never became one.
            Rule::OversizeClaim | Rule::MalformedClaim => Record::Counted,
            // Gate 1 (shape) — pure predicate, runs before we know who speaks.
            Rule::InvalidSenderId
            | Rule::MalformedClaimHash
            | Rule::EmptyClaim
            | Rule::TooManyEntries
            | Rule::EpochOutOfRange => Record::Counted,
            // Gate 2 (authenticity) — the last counter-only gate.
            Rule::SourceMismatch => Record::Counted,
            // `process_claim`'s own sender parse, likewise pre-authentication.
            Rule::UnparsableSender => Record::Counted,
            // Gates 3-8 — the identity has been bound, so the row is safe to
            // keep and an operator needs it.
            Rule::ClaimHashMismatch
            | Rule::StaleEpoch
            | Rule::EpochJumpTooLarge
            | Rule::AsnOutOfRange
            | Rule::UnassignedAsn
            | Rule::InvalidPrefix
            | Rule::Ipv4MappedPrefix
            | Rule::DefaultRoutePrefix
            | Rule::ConflictingEntry
            | Rule::SenderLimitExceeded
            | Rule::DuplicateSender => Record::Observed,
        }
    }

    /// Builds a settled engine, feeds it exactly one violating input, and
    /// asserts the full invariant. Exhaustive, no wildcard.
    fn exercise(self) {
        let reason = self.reason();
        let record = self.record();

        match self {
            // -- envelope ------------------------------------------------
            Rule::OversizeClaim => {
                let mut s = settled_default();
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.record_oversize_claim();
                    false
                });
            }
            Rule::MalformedClaim => {
                let mut s = settled_default();
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.record_malformed_claim();
                    false
                });
            }

            // -- Gate 1: shape -------------------------------------------
            Rule::InvalidSenderId => {
                let mut s = settled_default();
                let long = "a".repeat(MAX_SENDER_ID_LEN + 1);
                let c = claim(SETTLED_EPOCH, &long, vec![entry("1.2.3.0/24", 64512)]);
                let source = PeerId::random();
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });

                // The same rule is enforced on the offline path, before the
                // `PeerId` parse, so an overlong id is never parsed at all.
                let long = "a".repeat(MAX_SENDER_ID_LEN + 1);
                let c = claim(SETTLED_EPOCH, &long, vec![entry("1.2.3.0/24", 64512)]);
                assert_rejected(&mut s.engine, reason, record, |e| e.process_claim(c));
            }
            Rule::MalformedClaimHash => {
                let mut s = settled_default();

                // Wrong length.
                let (source, mut c) =
                    claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 64512)]);
                c.claim_hash = "deadbeef".to_string();
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });

                // Right length, but uppercase hex: `hex::encode` never emits
                // it, so accepting it would make one claim hashable two ways.
                let (source, mut c) =
                    claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 64512)]);
                c.claim_hash = c.claim_hash.to_uppercase();
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });

                // Right length and lowercase, but not hex at all.
                let (source, mut c) =
                    claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 64512)]);
                c.claim_hash = "z".repeat(64);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }
            Rule::EmptyClaim => {
                let mut s = settled_default();
                let (source, c) = claim_from_new_peer(SETTLED_EPOCH, vec![]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }
            Rule::TooManyEntries => {
                // The shipped cap is 2^21 entries, sized from a real full-map
                // measurement (§2.1). Building one here would cost more than
                // the whole suite, so the *injectable* limit is exercised
                // instead — which is what `ClaimLimits` is for.
                let limits = ClaimLimits {
                    max_entries: 3,
                    ..ClaimLimits::default()
                };
                let mut s = settled(limits);
                let (source, c) = claim_from_new_peer(
                    SETTLED_EPOCH,
                    vec![
                        entry("1.0.0.0/8", 1),
                        entry("2.0.0.0/8", 2),
                        entry("3.0.0.0/8", 3),
                        entry("4.0.0.0/8", 4),
                    ],
                );
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }
            Rule::EpochOutOfRange => {
                let mut s = settled_default();
                let (source, c) = claim_from_new_peer(u64::MAX, vec![entry("1.2.3.0/24", 64512)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }

            // -- Gate 2: authenticity ------------------------------------
            Rule::SourceMismatch => {
                let mut s = settled_default();
                let (_declared, c) =
                    claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 64512)]);
                let impostor = PeerId::random();
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &impostor)
                });
            }

            // -- Gate 3: integrity ---------------------------------------
            Rule::ClaimHashMismatch => {
                let mut s = settled_default();
                let (source, mut c) =
                    claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 64512)]);
                c.claim_hash = "0".repeat(64);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }

            // -- Gates 4 and 5: epoch ------------------------------------
            Rule::StaleEpoch => {
                let mut s = settled_default();
                let (source, c) =
                    claim_from_new_peer(SETTLED_EPOCH - 1, vec![entry("1.2.3.0/24", 64512)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }
            Rule::EpochJumpTooLarge => {
                let mut s = settled_default();
                let far = SETTLED_EPOCH + MAX_EPOCH_SKEW + 1;
                let (source, c) = claim_from_new_peer(far, vec![entry("1.2.3.0/24", 64512)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }

            // -- Gate 6: entries -----------------------------------------
            Rule::AsnOutOfRange => {
                let mut s = settled_default();
                let (source, c) =
                    claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", ASN_MAX + 1)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }
            Rule::UnassignedAsn => {
                let mut s = settled_default();
                let (source, c) = claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 0)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }
            Rule::InvalidPrefix => {
                let mut s = settled_default();

                // Unparsable text (§3 "parse" row).
                let (source, c) =
                    claim_from_new_peer(SETTLED_EPOCH, vec![entry("not-a-network", 64512)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });

                // Over-length text (§3 "raw" row) — rejected *before* parsing,
                // so the parser never sees an attacker-sized string.
                let oversize = format!("{}/24", "1".repeat(MAX_PREFIX_LEN));
                assert!(oversize.len() > MAX_PREFIX_LEN);
                let (source, c) = claim_from_new_peer(SETTLED_EPOCH, vec![entry(&oversize, 64512)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });

                // A prefix length past the family's width.
                let (source, c) =
                    claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/33", 64512)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }
            Rule::Ipv4MappedPrefix => {
                let mut s = settled_default();
                let (source, c) =
                    claim_from_new_peer(SETTLED_EPOCH, vec![entry("::ffff:1.2.3.0/120", 64512)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });

                // The hex spelling of the same range must not be a way round
                // it: Rust's `Display` normalizes it to the dotted-quad form,
                // but the check is on the address, not on the text.
                let (source, c) =
                    claim_from_new_peer(SETTLED_EPOCH, vec![entry("::ffff:0102:0300/120", 64512)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }
            Rule::DefaultRoutePrefix => {
                let mut s = settled_default();
                let (source, c) = claim_from_new_peer(SETTLED_EPOCH, vec![entry("::/0", 666)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }
            Rule::ConflictingEntry => {
                let mut s = settled_default();
                let (source, c) = claim_from_new_peer(
                    SETTLED_EPOCH,
                    vec![entry("1.2.3.0/24", 5), entry("1.2.3.0/24", 9)],
                );
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }

            // -- Gate 8: sender cap and dedupe ---------------------------
            Rule::SenderLimitExceeded => {
                // The settled engine already holds two senders, so a cap of two
                // is exactly full.
                let limits = ClaimLimits {
                    max_senders: 2,
                    ..ClaimLimits::default()
                };
                let mut s = settled(limits);
                let (source, c) =
                    claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 64512)]);
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &source)
                });
            }
            Rule::DuplicateSender => {
                let mut s = settled_default();
                // A *different* body from the same sender, so this proves the
                // second claim was not tallied rather than merely not counted:
                // if any of its prefixes reached `votes`, the snapshot moves.
                let peer = s.peers[0];
                let c = claim(
                    SETTLED_EPOCH,
                    &peer.to_string(),
                    vec![entry("9.9.9.0/24", 999)],
                );
                assert_rejected(&mut s.engine, reason, record, |e| {
                    e.process_claim_from_peer(c, &peer)
                });
                // And the second body's prefix never reached the report.
                let artifact = s.engine.finalize(TOPIC, LOCAL);
                assert!(
                    !artifact.entries.iter().any(|e| e.ip_prefix == "9.9.9.0/24"),
                    "a duplicate sender's second body must not be tallied"
                );
            }

            // -- `process_claim`'s own sender parse ----------------------
            Rule::UnparsableSender => {
                let mut s = settled_default();
                // Short enough to pass the length check, so this reaches the
                // parse rather than the shape gate. Previously a silent
                // `return false`: no observation, no counter, and so
                // `accepted + sum(rejected)` did not reconcile against input.
                let c = claim(SETTLED_EPOCH, "peer-a", vec![entry("1.2.3.0/24", 64512)]);
                assert_rejected(&mut s.engine, reason, record, |e| e.process_claim(c));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// One test per rule
// ---------------------------------------------------------------------------

#[test]
fn rejects_oversize_claim_without_moving_shared_state() {
    Rule::OversizeClaim.exercise();
}

#[test]
fn rejects_malformed_claim_without_moving_shared_state() {
    Rule::MalformedClaim.exercise();
}

#[test]
fn rejects_invalid_sender_id_without_moving_shared_state() {
    Rule::InvalidSenderId.exercise();
}

#[test]
fn rejects_source_mismatch_without_moving_shared_state() {
    Rule::SourceMismatch.exercise();
}

#[test]
fn rejects_malformed_claim_hash_without_moving_shared_state() {
    Rule::MalformedClaimHash.exercise();
}

#[test]
fn rejects_claim_hash_mismatch_without_moving_shared_state() {
    Rule::ClaimHashMismatch.exercise();
}

#[test]
fn rejects_empty_claim_without_moving_shared_state() {
    Rule::EmptyClaim.exercise();
}

#[test]
fn rejects_too_many_entries_without_moving_shared_state() {
    Rule::TooManyEntries.exercise();
}

#[test]
fn rejects_epoch_out_of_range_without_moving_shared_state() {
    Rule::EpochOutOfRange.exercise();
}

#[test]
fn rejects_stale_epoch_without_moving_shared_state() {
    Rule::StaleEpoch.exercise();
}

#[test]
fn rejects_epoch_jump_too_large_without_moving_shared_state() {
    Rule::EpochJumpTooLarge.exercise();
}

#[test]
fn rejects_asn_out_of_range_without_moving_shared_state() {
    Rule::AsnOutOfRange.exercise();
}

#[test]
fn rejects_unassigned_asn_without_moving_shared_state() {
    Rule::UnassignedAsn.exercise();
}

#[test]
fn rejects_invalid_prefix_without_moving_shared_state() {
    Rule::InvalidPrefix.exercise();
}

#[test]
fn rejects_ipv4_mapped_prefix_without_moving_shared_state() {
    Rule::Ipv4MappedPrefix.exercise();
}

#[test]
fn rejects_default_route_prefix_without_moving_shared_state() {
    Rule::DefaultRoutePrefix.exercise();
}

#[test]
fn rejects_conflicting_entry_without_moving_shared_state() {
    Rule::ConflictingEntry.exercise();
}

#[test]
fn rejects_sender_limit_exceeded_without_moving_shared_state() {
    Rule::SenderLimitExceeded.exercise();
}

#[test]
fn rejects_duplicate_sender_without_moving_shared_state() {
    Rule::DuplicateSender.exercise();
}

#[test]
fn rejects_unparsable_sender_without_moving_shared_state() {
    Rule::UnparsableSender.exercise();
}

// ---------------------------------------------------------------------------
// Meta-tests: the coverage guards
// ---------------------------------------------------------------------------

fn matrix_reasons() -> BTreeSet<String> {
    Rule::ALL.iter().map(|r| r.reason().to_string()).collect()
}

#[test]
fn every_rule_has_a_distinct_reason() {
    assert_eq!(
        matrix_reasons().len(),
        Rule::ALL.len(),
        "two rules share a reason string, so one of them is not really tested"
    );
}

/// A variant added to `Rule::ALL` but never given a `#[test]` of its own would
/// otherwise sit in the matrix contributing nothing.
#[test]
fn every_rule_is_exercised_by_a_named_test() {
    const THIS_FILE: &str = include_str!("claim_validation_matrix.rs");
    let missing: Vec<&str> = Rule::ALL
        .iter()
        .map(|r| r.reason())
        .filter(|reason| {
            !THIS_FILE.contains(&format!(
                "fn rejects_{reason}_without_moving_shared_state()"
            ))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "these rules are in the matrix but have no test of their own: {missing:?}"
    );
}

/// The load-bearing guard. A maintainer who adds a `count_rejection(..)` to
/// `src/lib.rs` and no test gets a red test naming the reason.
#[test]
fn every_reason_in_the_source_has_a_matrix_case() {
    let source = reasons_in_source();
    let matrix = matrix_reasons();

    let untested: Vec<&String> = source.difference(&matrix).collect();
    assert!(
        untested.is_empty(),
        "src/lib.rs can emit rejection reasons that this matrix does not \
         cover: {untested:?}. Add a `Rule` variant and a test."
    );

    let stale: Vec<&String> = matrix.difference(&source).collect();
    assert!(
        stale.is_empty(),
        "this matrix covers reasons src/lib.rs no longer emits: {stale:?}. \
         Either the rule was removed or the source scan has drifted."
    );
}

/// The specification is the contract; §6 of it requires every §3 row to have a
/// test. This asserts that mechanically rather than by review.
#[test]
fn every_reason_in_the_spec_has_a_matrix_case() {
    let spec = reasons_in_spec();
    let matrix = matrix_reasons();

    let untested: Vec<&String> = spec.difference(&matrix).collect();
    assert!(
        untested.is_empty(),
        "docs/CLAIM-VALIDATION.md §3 specifies rejection reasons with no test: \
         {untested:?}"
    );

    let unspecified: Vec<&String> = matrix.difference(&spec).collect();
    assert!(
        unspecified.is_empty(),
        "this matrix covers reasons the specification does not list: \
         {unspecified:?}. Update §3 or drop the rule."
    );
}

/// If the duplicated hash formula in `support/claims.rs` ever drifts from the
/// library's canonical form, this fails by name instead of every test in both
/// suites failing with an unexplained `claim_hash_mismatch`.
#[test]
fn the_test_helper_builds_claims_the_engine_accepts() {
    assert_helper_matches_the_engine();
}

// ---------------------------------------------------------------------------
// The ordering invariant, stated directly
// ---------------------------------------------------------------------------

/// The §4.2 reproduction: the claim that used to wipe a settled round.
///
/// Before the gate reorder this single message — a `u64::MAX` epoch with a
/// forged source *and* a garbage hash — advanced the engine at step 4, clearing
/// `seen_senders`, `votes`, `observations`, `accepted_claims` and
/// `rejected_claims`, and only then failed the source check at step 5. The
/// round was destroyed by a claim that never passed a single gate, and the
/// epoch was pinned at `u64::MAX` so every honest claim afterwards was
/// `stale_epoch` forever.
#[test]
fn the_hostile_epoch_claim_no_longer_wipes_a_settled_round() {
    let mut s = settled_default();
    let before = snapshot(&s.engine);

    // The original message: an unreachable epoch, a forged source and a
    // garbage hash. Now stopped at Gate 1 by the epoch ceiling alone.
    let mut hostile = claim(u64::MAX, "unrelated", vec![entry("1.2.3.0/24", 64512)]);
    hostile.claim_hash = "0".repeat(64);
    let impostor = PeerId::random();
    assert!(!s.engine.process_claim_from_peer(hostile, &impostor));

    // The ceiling on its own is not the fix, so here is the same attack from
    // inside it: the largest epoch the engine *would* adopt, forged source,
    // valid-looking hash. Under the pre-PR order this reached `advance_epoch`
    // before the source check and wiped the round; it must now die at Gate 2.
    let adoptable = SETTLED_EPOCH + MAX_EPOCH_SKEW;
    let (_declared, sneaky) = claim_from_new_peer(adoptable, vec![entry("1.2.3.0/24", 64512)]);
    assert!(!s.engine.process_claim_from_peer(sneaky, &PeerId::random()));

    // And once more with a source that *does* match, so the claim is
    // authenticated, but carrying an out-of-domain entry. Gate 6 runs ahead of
    // the Gate 7 adoption, so this cannot move the engine either.
    let (source, poisoned) = claim_from_new_peer(adoptable, vec![entry("1.2.3.0/24", 0)]);
    assert!(!s.engine.process_claim_from_peer(poisoned, &source));

    let after = snapshot(&s.engine);
    assert_eq!(after.epoch, SETTLED_EPOCH, "the epoch must not have moved");
    assert_eq!(
        after.shared_state, before.shared_state,
        "the settled round must survive a claim that passed no gate"
    );

    // And the honest senders are still able to work: an epoch that never moved
    // means no honest claim has become stale.
    let (source, c) = claim_from_new_peer(SETTLED_EPOCH, vec![entry("10.0.0.0/8", 100)]);
    assert!(s.engine.process_claim_from_peer(c, &source));
    let artifact = s.engine.finalize(TOPIC, LOCAL);
    assert_eq!(artifact.accepted_claims, 3);
    assert_eq!(artifact.epoch, SETTLED_EPOCH);
}

/// The stronger invariant the implemented order buys, stated as its own test:
/// entry validation runs *before* epoch adoption, so a claim rejected for its
/// entries cannot move the engine forward on the way out.
#[test]
fn a_future_claim_rejected_for_its_entries_does_not_advance_the_epoch() {
    let mut s = settled_default();
    let future = SETTLED_EPOCH + 100; // well inside MAX_EPOCH_SKEW
    let (source, c) = claim_from_new_peer(future, vec![entry("1.2.3.0/24", 0)]);

    assert_rejected(&mut s.engine, "unassigned_asn", Record::Observed, |e| {
        e.process_claim_from_peer(c, &source)
    });
    assert_eq!(
        s.engine.epoch(),
        SETTLED_EPOCH,
        "a claim rejected at Gate 6 must not reach the Gate 7 adoption"
    );
}

/// The other half of the same rule: catch-up is deliberately preserved. A claim
/// that passes *every* gate does advance the engine, and does clear the round —
/// that is how a late-joining node synchronises, and it must keep working.
#[test]
fn a_future_claim_that_passes_every_gate_still_advances_the_epoch() {
    let mut s = settled_default();
    let future = SETTLED_EPOCH + 100;
    let (source, c) = claim_from_new_peer(future, vec![entry("1.2.3.0/24", 64512)]);

    assert!(!s.engine.process_claim_from_peer(c, &source));
    let artifact = s.engine.finalize(TOPIC, LOCAL);
    assert_eq!(artifact.epoch, future);
    assert_eq!(
        artifact.accepted_claims, 1,
        "adoption clears the round, keeping only the claim that caused it"
    );
    assert_eq!(artifact.participants.len(), 1);
    assert!(artifact.entries.is_empty(), "threshold 2, one sender");
}

/// The epoch ceiling must not become a ratchet an attacker walks upward one
/// skew window at a time, so a claim-driven adoption never raises it — only the
/// local `advance_epoch` does.
#[test]
fn a_claim_driven_advance_does_not_raise_the_epoch_ceiling() {
    let limits = ClaimLimits {
        max_epoch: SETTLED_EPOCH + 200,
        max_epoch_skew: 100,
        ..ClaimLimits::default()
    };
    let mut s = settled(limits);
    let ceiling = s.engine.limits().max_epoch;

    let (source, c) = claim_from_new_peer(SETTLED_EPOCH + 100, vec![entry("1.2.3.0/24", 1)]);
    assert!(!s.engine.process_claim_from_peer(c, &source));
    assert_eq!(
        s.engine.limits().max_epoch,
        ceiling,
        "adopting a claimed epoch must not raise the ceiling"
    );

    // The local path may raise it, which is what keeps a long-lived node whose
    // own counter walks past its starting ceiling able to accept claims.
    s.engine.advance_epoch(ceiling);
    assert!(s.engine.limits().max_epoch > ceiling);
}

// ---------------------------------------------------------------------------
// Rows of §3 that are not rejection reasons
// ---------------------------------------------------------------------------

/// §3, `QuorumEngine.observations` row. The cap is deliberately *not* a
/// rejection reason: a log-overflow marker is not a claim, and counting it as
/// one would break the reconciliation identity below. Retention stops; counting
/// does not.
#[test]
fn rejection_observations_are_capped_while_the_counter_keeps_counting() {
    let limits = ClaimLimits {
        max_rejection_observations: 8,
        ..ClaimLimits::default()
    };
    let mut s = settled(limits);
    let accepted_rows = s.engine.finalize(TOPIC, LOCAL).observations.len();

    for _ in 0..64 {
        let (source, mut c) = claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 64512)]);
        c.claim_hash = "0".repeat(64);
        assert!(!s.engine.process_claim_from_peer(c, &source));
    }

    let artifact = s.engine.finalize(TOPIC, LOCAL);
    assert_eq!(
        artifact.rejected_claims.get("claim_hash_mismatch"),
        Some(&64),
        "the aggregate must survive the retention cap"
    );
    assert_eq!(
        artifact.observations.len(),
        accepted_rows + 8,
        "rejection rows must stop at the cap"
    );
    // The accepted rows are never crowded out: letting rejections evict them
    // would hand an attacker a way to erase the record of the honest claims.
    assert_eq!(
        artifact.observations.iter().filter(|o| o.accepted).count(),
        accepted_rows
    );
}

/// §6.3, the reconciliation identity an operator is asked to perform:
/// `accepted_claims + sum(rejected_claims)` equals the number of claims fed in.
/// This is what the silent-drop paths used to break.
#[test]
fn every_claim_is_accounted_for_exactly_once() {
    let mut engine = QuorumEngine::with_limits(2, SETTLED_EPOCH, ClaimLimits::default());
    let mut fed = 0usize;

    // Two good ones.
    for _ in 0..2 {
        let (source, c) = claim_from_new_peer(SETTLED_EPOCH, vec![entry("10.0.0.0/8", 100)]);
        engine.process_claim_from_peer(c, &source);
        fed += 1;
    }
    // One of every counter-only shape, which is where claims used to vanish.
    let long = "a".repeat(MAX_SENDER_ID_LEN + 1);
    let bad_shapes = vec![
        claim(SETTLED_EPOCH, &long, vec![entry("1.2.3.0/24", 1)]),
        claim(SETTLED_EPOCH, "peer-a", vec![entry("1.2.3.0/24", 1)]),
        claim(u64::MAX, "peer-a", vec![entry("1.2.3.0/24", 1)]),
    ];
    for c in bad_shapes {
        engine.process_claim(c);
        fed += 1;
    }
    // And one of every observed shape.
    let observed: Vec<_> = vec![
        (SETTLED_EPOCH - 1, entry("1.2.3.0/24", 1)),
        (SETTLED_EPOCH, entry("1.2.3.0/24", 0)),
        (SETTLED_EPOCH, entry("::/0", 1)),
        (SETTLED_EPOCH, entry("::ffff:1.2.3.0/120", 1)),
        (SETTLED_EPOCH, entry("not-a-network", 1)),
    ];
    for (epoch, e) in observed {
        let (source, c) = claim_from_new_peer(epoch, vec![e]);
        engine.process_claim_from_peer(c, &source);
        fed += 1;
    }

    let artifact = engine.finalize(TOPIC, LOCAL);
    let rejected: usize = artifact.rejected_claims.values().sum();
    assert_eq!(
        artifact.accepted_claims + rejected,
        fed,
        "every claim must produce exactly one accounting event; \
         accepted={} rejected={:?}",
        artifact.accepted_claims,
        artifact.rejected_claims
    );
}

/// §3, intra-claim row, the half that must *not* reject: a sender repeating the
/// identical `(prefix, asn)` is harmless and simply dedupes to one vote. Only a
/// prefix asserted with two different ASNs is self-contradictory.
#[test]
fn a_repeated_identical_entry_dedupes_rather_than_rejecting() {
    let mut engine = QuorumEngine::with_limits(1, SETTLED_EPOCH, ClaimLimits::default());
    let (source, c) = claim_from_new_peer(
        SETTLED_EPOCH,
        vec![
            entry("1.2.3.0/24", 64512),
            entry("1.2.3.0/24", 64512),
            entry("1.2.3.0/24", 64512),
        ],
    );

    assert!(engine.process_claim_from_peer(c, &source));
    let artifact = engine.finalize(TOPIC, LOCAL);
    assert!(artifact.rejected_claims.is_empty());
    assert_eq!(artifact.entries.len(), 1);
    assert_eq!(
        artifact.entries[0].votes, 1,
        "one sender must cast one vote however many times it repeats itself"
    );
}

/// A claim that violates nothing is still accepted, entry for entry. Without
/// this the whole suite could pass with an engine that rejects everything.
///
/// The last three entries are the *shortest prefixes that actually occur* in
/// the flat form of the 29 snapshots under `data/` (`224.0.0.0/3`, `1000::/4`)
/// plus the upper half of IPv6. They are here on purpose: they are the closest
/// honest data comes to the prefixes Gate 6 rejects, so a specificity rule
/// greedy enough to stop `::/1` would break this test first. This is the test
/// that says the entry gates may not be tightened into a minimum prefix length.
#[test]
fn a_well_formed_claim_is_still_accepted_whole() {
    let mut engine = QuorumEngine::with_limits(1, SETTLED_EPOCH, ClaimLimits::default());
    let entries = vec![
        entry("1.0.0.0/8", 1),
        entry("2.0.0.0/8", 2),
        entry("2001:db8::/32", 3),
        entry("224.0.0.0/3", 16509),
        entry("1000::/4", 16509),
        entry("8000::/1", 140810),
    ];
    let (source, c) = claim_from_new_peer(SETTLED_EPOCH, entries.clone());

    assert!(engine.process_claim_from_peer(c, &source));
    let artifact = engine.finalize(TOPIC, LOCAL);
    assert!(artifact.rejected_claims.is_empty());
    assert_eq!(artifact.entries.len(), entries.len());
    assert_eq!(artifact.accepted_claims, 1);
    claims::assert_accepted_observation(&artifact, &source.to_string());
}

/// A rejection record must carry what the peer actually asserted, not what the
/// engine wished for. Before this PR `record_rejection` was passed the locally
/// recomputed hash and `self.epoch`, so the observation log silently lost the
/// evidence and was useless for attributing an attack.
#[test]
fn a_rejection_record_carries_the_values_the_peer_sent() {
    let mut s = settled_default();

    let (source, mut c) = claim_from_new_peer(SETTLED_EPOCH, vec![entry("1.2.3.0/24", 64512)]);
    let asserted_hash = "a".repeat(64);
    c.claim_hash = asserted_hash.clone();
    assert!(!s.engine.process_claim_from_peer(c, &source));

    let stale_epoch = SETTLED_EPOCH - 4;
    let (source2, c2) = claim_from_new_peer(stale_epoch, vec![entry("1.2.3.0/24", 64512)]);
    let sealed_hash = c2.claim_hash.clone();
    assert!(!s.engine.process_claim_from_peer(c2, &source2));

    let artifact = s.engine.finalize(TOPIC, LOCAL);
    let rows: Vec<_> = artifact
        .observations
        .iter()
        .filter(|o| !o.accepted)
        .collect();
    assert_eq!(rows.len(), 2);

    assert_eq!(rows[0].reason, "claim_hash_mismatch");
    assert_eq!(
        rows[0].claim_hash, asserted_hash,
        "the record must show the hash the peer sent, not the expected one"
    );

    assert_eq!(rows[1].reason, "stale_epoch");
    assert_eq!(
        rows[1].epoch, stale_epoch,
        "the record must show the epoch the peer claimed, not the engine's"
    );
    assert_eq!(rows[1].claim_hash, sealed_hash);
}

/// A `Settled` is only useful if it really is settled; this pins the fixture so
/// a change to it cannot silently weaken every test above.
#[test]
fn the_settled_fixture_is_actually_settled() {
    let s: Settled = settled_default();
    let artifact = s.engine.finalize(TOPIC, LOCAL);
    assert_eq!(artifact.epoch, SETTLED_EPOCH);
    assert_eq!(artifact.threshold, 2);
    assert_eq!(artifact.participants.len(), 2);
    assert_eq!(artifact.accepted_claims, 2);
    assert_eq!(artifact.entries.len(), 1);
    assert_eq!(artifact.entries[0].ip_prefix, "10.0.0.0/8");
    assert_eq!(artifact.entries[0].asn, 100);
    assert_eq!(artifact.entries[0].votes, 2);
    assert!(!artifact.map.to_entries(false, false).is_empty());
    assert_eq!(s.claims.len(), 2);
    assert_eq!(s.peers.len(), 2);
}
