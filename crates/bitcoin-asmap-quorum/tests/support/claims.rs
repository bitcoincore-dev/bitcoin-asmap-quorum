//! Claim construction and engine-state assertions shared by the two
//! ingest-path suites.
//!
//! Included with `#[path]` by `claim_validation_matrix.rs` and
//! `quorum_disagreement.rs` rather than compiled as its own test target
//! (`tests/support/` is not auto-discovered by Cargo).
//!
//! # Why the claim hash is re-derived here
//!
//! `claim_hash()` and `canonical_claim_bytes()` are private to the library, and
//! `asmap_to_claim()` is too, so there is no public way to construct a claim the
//! engine will accept. An integration test — which sees only the public API,
//! exactly as a downstream consumer does — has to recompute the digest. That
//! duplication is deliberate but it is also a liability, so
//! [`assert_helper_matches_the_engine`] pins it: if the canonical form ever
//! drifts, one named test fails instead of every test in both suites failing
//! with an unexplained `claim_hash_mismatch`.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use bitcoin_asmap_quorum::{AsmapClaim, AsmapEntry, ClaimLimits, ConsensusArtifact, QuorumEngine};
use libp2p::PeerId;
use sha2::{Digest, Sha256};

/// Topic and local peer id used for every `finalize()` in these suites. Fixed,
/// so a snapshot diff can never be explained by the arguments.
pub const TOPIC: &str = "bitcoin-asmap-quorum";
pub const LOCAL: &str = "test-local-peer";

/// The epoch every settled engine in these suites starts at.
pub const SETTLED_EPOCH: u64 = 7;

// ---------------------------------------------------------------------------
// Claim construction
// ---------------------------------------------------------------------------

/// One well-formed entry, so a test can vary exactly one thing.
pub fn entry(ip_prefix: &str, asn: u32) -> AsmapEntry {
    AsmapEntry {
        ip_prefix: ip_prefix.to_string(),
        asn,
    }
}

/// Re-derivation of the library's private `claim_hash`.
///
/// Kept structurally identical to `canonical_claim_bytes` — sort by
/// `(ip_prefix, asn)`, then `epoch=`/`sender=` header lines, then one
/// `{prefix}|{asn}` line per entry — so a reviewer can diff the two by eye.
pub fn claim_hash(epoch: u64, sender_id: &str, entries: &[AsmapEntry]) -> String {
    let mut entries = entries.to_vec();
    entries.sort_by(|a, b| {
        a.ip_prefix
            .cmp(&b.ip_prefix)
            .then_with(|| a.asn.cmp(&b.asn))
    });

    let mut bytes = Vec::new();
    bytes.extend_from_slice(format!("epoch={epoch}\nsender={sender_id}\n").as_bytes());
    for entry in &entries {
        bytes.extend_from_slice(format!("{}|{}\n", entry.ip_prefix, entry.asn).as_bytes());
    }

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// A claim carrying a correct hash for the given sender and entries.
pub fn claim(epoch: u64, sender_id: &str, entries: Vec<AsmapEntry>) -> AsmapClaim {
    let claim_hash = claim_hash(epoch, sender_id, &entries);
    AsmapClaim {
        epoch,
        sender_id: sender_id.to_string(),
        claim_hash,
        entries,
    }
}

/// A claim from a fresh identity, valid unless the caller mutates it.
pub fn claim_from_new_peer(epoch: u64, entries: Vec<AsmapEntry>) -> (PeerId, AsmapClaim) {
    let peer = PeerId::random();
    let claim = claim(epoch, &peer.to_string(), entries);
    (peer, claim)
}

/// Recomputes and reinstalls the hash after a test has mutated a claim, so that
/// a test targeting some *other* gate is not accidentally rejected at Gate 3.
pub fn reseal(mut claim: AsmapClaim) -> AsmapClaim {
    claim.claim_hash = claim_hash(claim.epoch, &claim.sender_id, &claim.entries);
    claim
}

// ---------------------------------------------------------------------------
// A settled engine: real state for a rejected claim to fail to disturb
// ---------------------------------------------------------------------------

/// An engine that has already reached consensus, plus the material needed to
/// replay one of its accepted claims.
pub struct Settled {
    pub engine: QuorumEngine,
    pub peers: Vec<PeerId>,
    pub claims: Vec<AsmapClaim>,
}

/// Threshold 2 at epoch [`SETTLED_EPOCH`], with two accepted senders that agree
/// on `10.0.0.0/8 -> AS100` and disagree about everything else.
///
/// The disagreement is load-bearing: it puts sub-threshold keys in `votes`, so
/// a test that accidentally moves the tally shows up in the snapshot even when
/// the consensus *entries* would be unchanged.
pub fn settled(limits: ClaimLimits) -> Settled {
    let mut engine = QuorumEngine::with_limits(2, SETTLED_EPOCH, limits);

    let (peer_a, claim_a) = claim_from_new_peer(
        SETTLED_EPOCH,
        vec![entry("10.0.0.0/8", 100), entry("2.0.0.0/8", 200)],
    );
    let (peer_b, claim_b) = claim_from_new_peer(
        SETTLED_EPOCH,
        vec![entry("10.0.0.0/8", 100), entry("3.0.0.0/8", 300)],
    );

    assert!(
        !engine.process_claim_from_peer(claim_a.clone(), &peer_a),
        "first of two claims must not yet signal quorum"
    );
    assert!(
        engine.process_claim_from_peer(claim_b.clone(), &peer_b),
        "second claim must reach the threshold of 2"
    );

    let artifact = engine.finalize(TOPIC, LOCAL);
    assert_eq!(
        artifact.accepted_claims, 2,
        "settled engine must be settled"
    );
    assert_eq!(
        artifact.entries.len(),
        1,
        "one prefix should clear threshold"
    );
    assert!(
        artifact.rejected_claims.is_empty(),
        "settled engine must start with a clean rejection ledger"
    );

    Settled {
        engine,
        peers: vec![peer_a, peer_b],
        claims: vec![claim_a, claim_b],
    }
}

/// [`settled`] with the library's clock-free default limits.
pub fn settled_default() -> Settled {
    settled(ClaimLimits::default())
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

/// Everything a rejected claim is forbidden to move.
///
/// `ConsensusArtifact` has no `PartialEq`, so the comparison goes through
/// `serde_json::Value`. The two accounting fields — `rejected_claims` and
/// `observations` — are deliberately *excluded* here and asserted separately:
/// they are the only two a rejection is allowed to touch.
pub struct Snapshot {
    pub epoch: u64,
    pub shared_state: serde_json::Value,
    pub rejected_claims: BTreeMap<String, usize>,
    pub observation_count: usize,
    pub last_observation_reason: Option<String>,
}

pub fn snapshot(engine: &QuorumEngine) -> Snapshot {
    let artifact = engine.finalize(TOPIC, LOCAL);
    Snapshot {
        epoch: engine.epoch(),
        shared_state: shared_state_of(&artifact),
        rejected_claims: artifact.rejected_claims.clone(),
        observation_count: artifact.observations.len(),
        last_observation_reason: artifact.observations.last().map(|o| o.reason.clone()),
    }
}

fn shared_state_of(artifact: &ConsensusArtifact) -> serde_json::Value {
    serde_json::json!({
        "epoch": artifact.epoch,
        "topic": artifact.topic,
        "threshold": artifact.threshold,
        "participants": artifact.participants,
        "accepted_claims": artifact.accepted_claims,
        "entries": serde_json::to_value(&artifact.entries).unwrap(),
        "map": serde_json::to_value(&artifact.map).unwrap(),
    })
}

// ---------------------------------------------------------------------------
// The invariant every rejection case asserts
// ---------------------------------------------------------------------------

/// Whether a rejection is expected to leave a row in `observations`.
///
/// Counter-only rejections are not an oversight: `docs/CLAIM-VALIDATION.md` §3
/// suppresses the observation for every pre-authentication rejection, because a
/// `ClaimObservation` retains the sender's own string and that is precisely the
/// unbounded-growth vector the gate reorder exists to close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    /// Counted in `rejected_claims`, with no `observations` row.
    Counted,
    /// Counted *and* recorded, with `accepted: false` and the named reason.
    Observed,
}

/// Runs `feed` against `engine` and asserts the full rejection invariant.
///
/// 1. the call returned `false`;
/// 2. `rejected_claims[reason]` grew by exactly 1, and **no other** reason
///    counter moved;
/// 3. `observations` grew by exactly 0 or 1 per `record`, and a new row carries
///    `accepted: false` with the expected reason;
/// 4. `epoch`, `participants`, `accepted_claims`, `entries`, `map`, `threshold`
///    and `topic` are byte-identical to the pre-state.
///
/// (4) is the one that matters. A per-reason test that only checks the counter
/// passes just as happily with the gates in the wrong order — which is how the
/// pre-`claim-validation` engine could let a claim it was about to reject wipe
/// the entire round first.
pub fn assert_rejected(
    engine: &mut QuorumEngine,
    reason: &str,
    record: Record,
    feed: impl FnOnce(&mut QuorumEngine) -> bool,
) {
    let before = snapshot(engine);
    let accepted = feed(engine);
    let after = snapshot(engine);

    assert!(!accepted, "[{reason}] the claim must be rejected");

    // (2) exactly one counter, incremented exactly once.
    let mut expected_counters = before.rejected_claims.clone();
    *expected_counters.entry(reason.to_string()).or_insert(0) += 1;
    assert_eq!(
        after.rejected_claims, expected_counters,
        "[{reason}] rejection counters moved in an unexpected way; \
         before={:?} after={:?}",
        before.rejected_claims, after.rejected_claims
    );

    // (3) observation growth, bounded and attributed.
    match record {
        Record::Counted => assert_eq!(
            after.observation_count, before.observation_count,
            "[{reason}] a pre-authentication rejection must not retain an \
             attacker-supplied observation row"
        ),
        Record::Observed => {
            assert_eq!(
                after.observation_count,
                before.observation_count + 1,
                "[{reason}] expected exactly one new observation"
            );
            assert_eq!(
                after.last_observation_reason.as_deref(),
                Some(reason),
                "[{reason}] the new observation carries the wrong reason"
            );
        }
    }

    // (4) nothing else moved.
    assert_eq!(
        after.epoch, before.epoch,
        "[{reason}] a rejected claim moved the engine's epoch"
    );
    assert_eq!(
        after.shared_state, before.shared_state,
        "[{reason}] a rejected claim mutated shared consensus state"
    );
}

/// Asserts that the last observation is an accepted one for `sender_id`.
pub fn assert_accepted_observation(artifact: &ConsensusArtifact, sender_id: &str) {
    let last = artifact
        .observations
        .last()
        .expect("an accepted claim must leave an observation");
    assert!(last.accepted, "expected an accepted observation");
    assert_eq!(last.reason, "accepted");
    assert_eq!(last.sender_id, sender_id);
}

// ---------------------------------------------------------------------------
// Self-check on the duplicated hash formula
// ---------------------------------------------------------------------------

/// Proves the re-derivation above still matches the engine.
pub fn assert_helper_matches_the_engine() {
    let mut engine = QuorumEngine::with_limits(1, 1, ClaimLimits::default());
    let (peer, claim) = claim_from_new_peer(1, vec![entry("1.2.3.0/24", 64512)]);
    assert!(
        engine.process_claim_from_peer(claim, &peer),
        "the helper's claim_hash no longer matches the library's canonical \
         form; every other test in these suites will fail with \
         claim_hash_mismatch until this is resynchronised"
    );
    let artifact = engine.finalize(TOPIC, LOCAL);
    assert!(artifact.rejected_claims.is_empty());
    assert_eq!(artifact.accepted_claims, 1);
}

// ---------------------------------------------------------------------------
// Reason-set extraction, for the coverage meta-tests
// ---------------------------------------------------------------------------

/// Every rejection reason literal in `impl QuorumEngine`.
///
/// Scanned from the source rather than hard-coded, so that a maintainer who
/// adds `count_rejection("oversized_claim")` and no test gets a red test naming
/// the reason. The scan is confined to the `impl QuorumEngine` block and to the
/// four syntactic positions a reason can occupy:
///
/// - `Some("...")` returned by `shape_violation`
/// - `Err("...")` returned by `validated_vote_keys`
/// - `count_rejection("...")`
/// - the final argument of `record_rejection`, which rustfmt always puts on its
///   own line as `"...",`
///
/// [`is_reason_shaped`] keeps non-reason literals such as `Some("-")` out.
pub fn reasons_in_source() -> BTreeSet<String> {
    const SOURCE: &str = include_str!("../../src/lib.rs");

    let body = impl_quorum_engine_body(SOURCE);
    let mut found = BTreeSet::new();
    for line in body.lines() {
        let trimmed = line.trim();
        let candidate = literal_after(trimmed, "count_rejection(\"")
            .or_else(|| literal_after(trimmed, "Some(\""))
            .or_else(|| literal_after(trimmed, "Err(\""))
            .or_else(|| {
                trimmed
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix("\","))
                    .map(str::to_string)
            });
        if let Some(reason) = candidate
            && is_reason_shaped(&reason)
        {
            found.insert(reason);
        }
    }
    assert!(
        !found.is_empty(),
        "the source scan found no rejection reasons at all; the scan itself \
         has broken and every coverage claim built on it is vacuous"
    );
    found
}

/// Shape of a rejection reason: `snake_case`, ASCII lowercase and digits, at
/// least one `_`. Digits matter — `ipv4_mapped_prefix` has one, and a filter
/// that excluded them silently dropped a real rule from the coverage check.
fn is_reason_shaped(token: &str) -> bool {
    token.contains('_')
        && token
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn literal_after(line: &str, opener: &str) -> Option<String> {
    let rest = line.split_once(opener)?.1;
    let (literal, _) = rest.split_once('"')?;
    Some(literal.to_string())
}

fn impl_quorum_engine_body(source: &str) -> &str {
    let start = source
        .find("\nimpl QuorumEngine {")
        .expect("impl QuorumEngine block not found; the source scan needs updating");
    let end = source[start..]
        .find("\nfn asmap_to_claim")
        .expect("end of impl QuorumEngine not found; the source scan needs updating");
    &source[start..start + end]
}

/// Every rejection reason named in the §3 table of
/// `docs/CLAIM-VALIDATION.md` — the specification this PR implements.
///
/// The table's last column holds the reason(s) for each row, backticked. A row
/// with no reason (`*(none — see below)*`) contributes nothing.
pub fn reasons_in_spec() -> BTreeSet<String> {
    const SPEC: &str = include_str!("../../../../docs/CLAIM-VALIDATION.md");

    let table = section_three_table(SPEC);
    let mut found = BTreeSet::new();
    for row in table {
        let cells: Vec<&str> = row.trim().trim_matches('|').split('|').collect();
        let Some(last) = cells.last() else { continue };
        for token in last.split('`').skip(1).step_by(2) {
            if is_reason_shaped(token) {
                found.insert(token.to_string());
            }
        }
    }
    assert!(
        !found.is_empty(),
        "the spec scan found no rejection reasons at all; the scan itself has \
         broken and every coverage claim built on it is vacuous"
    );
    found
}

fn section_three_table(spec: &str) -> Vec<&str> {
    let start = spec
        .find("| Field | Type | Valid domain | Enforced at | Rejection reason |")
        .expect("the §3 table header moved; the spec scan needs updating");
    spec[start..]
        .lines()
        .skip(2) // header and separator
        .take_while(|line| line.starts_with('|'))
        .collect()
}
