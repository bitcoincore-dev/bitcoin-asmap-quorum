# Claim validation specification

Status: **implemented** by the `claim-validation` PR. Line references are to
`crates/bitcoin-asmap-quorum/src/lib.rs` as of the `codec-crate` base commit
(`91b6ba2`), i.e. they describe the code *being changed*, not the code as it
stands after the change.

Two things were settled by measurement during implementation and are recorded in
place below rather than left as they were first written: `MAX_CLAIM_ENTRIES`
(§2.1) and the retention policy for `observations` (§3). Both are marked where
they changed.

A second round of measurement followed review, and corrected this document as
well as the code. Three claims made here were wrong: that IPv4 `/0` is harmless
(§3.1), that the epoch ceiling could not be widened by input (§4.3.1), and that
"no unbounded input" held on the file path (§1). What is *not* fixed, and why,
is in §8 — it is a shorter list than it would be if the tempting fix for the
entry gates worked, and §3.1 records the measurement that says it does not.

## 1. Purpose

Every value that reaches the quorum engine from outside the process has a
**stated valid domain**, is **checked at a stated place**, and fails with a
**named rejection reason** that appears in the consensus report.

That is the whole of the contract. Three properties follow from it, and they are
the reason the work is worth doing:

1. **No unbounded input on the network path.** Every string, collection and
   integer that an attacker controls has an explicit ceiling, so message volume
   cannot be converted into heap, disk or CPU without limit. The scope of
   *network* is load-bearing and an earlier draft over-claimed it: `replay`
   reads its whole claims file into memory before any gate runs
   (`std::fs::read_to_string`, then `serde_json::from_str::<Vec<AsmapClaim>>`)
   and imposes no byte cap. That is an accepted limitation, recorded in §2.1 and
   §8 — not a property that holds. One integer on the file path *is* now bounded
   that was not: the engine's **starting epoch**, which `replay` reads from
   `claims[0].epoch` when `--epoch` is omitted (§4.3.1).
2. **No silent loss.** Every claim that is dropped is counted under a named
   reason. Today several inputs vanish with no observation and no counter, so
   `artifact.observations.len()` does not reconcile against the input, which is
   exactly the reconciliation `docs/OPERATOR_GUIDE.md` asks operators to
   perform.
3. **No state mutation before authenticity.** A claim that will be rejected
   must not be able to change the engine first. This is currently violated, and
   it is the most serious defect this PR addresses (§4).

"Outside the process" means both the gossip path (`process_claim_from_peer`,
reached from `serve` at L1392 and `collect` at L1591) and the offline path
(`process_claim` at L861, reached from `replay` at L2290). The trust models
differ (§5) but the *validation* is identical, because the ordering defect bites
on both — see the reproduction in §4.2, which needs no network at all.

### What this layer does not buy

Stated plainly, because the rest of this document is easy to over-read:
**claims are not signed.** `claim_hash` is an unsigned SHA-256 over
`(epoch, sender_id, entries)` — every input is chosen by the sender — so any
attacker computes a passing value for free. It detects truncation and codec
drift. It is not evidence of anything.

"Authenticity" in this document therefore means one narrow thing: *the libp2p
transport source matches the `sender_id` the claim declares*. Since libp2p
PeerIds cost an ed25519 keygen to mint and there is no participant allowlist, a
single host satisfies that check for as many distinct identities as it likes,
and so reaches any `threshold` unaided (default 3, `README.md:232`).

**This specification bounds the damage a claim can do. It does not establish who
may make one.** Sybil resistance requires an identity model — an operator
roster, signed claims, or both — which is deliberately out of scope (§6). A
determined attacker who can reach the topic can still reach quorum. What changes
is that reaching quorum no longer lets them panic the node, silently poison the
map, or make the output nondeterministic.

## 2. Constants

All of these are `pub const` in `lib.rs`. Everything an operator might need to
vary per deployment is also a field of `ClaimLimits`, which is injected at
[`QuorumEngine::with_limits`] rather than read from the environment or the
clock inside the tally.

| Constant | Value | Basis |
| --- | --- | --- |
| `MAX_CLAIM_BYTES` | `65_536` | Set explicitly via `gossipsub::ConfigBuilder::max_transmit_size`, not inherited; see §2.1 |
| `MAX_CLAIM_ENTRIES` | `2_097_152` (2^21) | **Measured**, not assumed: a real asmap expands to 741,964 claim entries. See §2.1 |
| `MIN_CLAIM_ENTRIES` | `1` | An empty claim carries no information but consumes a `threshold` slot |
| `MAX_SENDER_ID_LEN` | `64` | base58btc PeerId text is 46–52 chars in practice; generous headroom |
| `CLAIM_HASH_LEN` | `64` | `hex::encode` of a SHA-256 digest, exactly |
| `MAX_PREFIX_LEN` | `49` | Longest IPv6 text form (45) + `/` + 3 digits. Real data tops out at 42 |
| `ASN_MIN` / `ASN_MAX` | `1` / `33_521_664` | Hard wire-format limit of `CODER_ASN`, derived in §3.1. Real data tops out at 4,020,790 |
| `EPOCH_ABSOLUTE_MAX` | `4_102_444_800` | 2100-01-01 as Unix seconds; see §2.2 |
| `MAX_EPOCH_SKEW` | `86_400` | One day of seconds under the timestamp reading; far above a day of `+1` ticks under the counter reading |
| `MAX_SENDERS` | `1_024` | Round participant cap; bounds `seen_senders` and, with `MAX_CLAIM_ENTRIES`, `votes` |
| `MAX_REJECTION_OBSERVATIONS` | `1_024` | Retention cap on *rejection* observations; see §3 |

### 2.1 `MAX_CLAIM_BYTES` is an accident; `MAX_CLAIM_ENTRIES` is now measured

`L762-765` builds the gossipsub config setting only `heartbeat_interval`, so
`max_transmit_size` sits at libp2p-gossipsub 0.46.1's default of **65536 bytes**.
Nothing in this repository chose that number and a dependency bump can change it
silently. It must be set explicitly.

It is nonetheless left at 64 KiB, because raising it is a DoS-surface decision
and not a bounds-checking one. What the measurement below establishes is that
the number is far too small for a full claim, so the design question is real:

**Measured.** `asmap_to_claim` builds entries from `to_entries(false, false)` —
the *flat*, non-overlapping form, not the overlapping text form. Decoding
`data/latest_asmap.dat` (a real Bitcoin Core asmap) gives 410,311 lines of
overlapping text but **741,964 flat entries**, and `import`ing it produces a
58 MB claim JSON. Against that:

- `MAX_CLAIM_ENTRIES` is set to `2_097_152` (2^21), ~2.8x the largest honest
  claim actually observed. The originally specified `131_072` would have
  rejected a fully honest full-map claim outright — verified: it does, with
  `too_many_entries`.
- 64 KiB is roughly 2000 minimal entries, so **the gossip path still cannot
  carry a full claim**, by a factor of ~400. Whatever claims flow over it today
  are small or partial. Chunking, compression, or an explicitly partial-claim
  model is a design question this PR surfaces rather than settles. **Open item
  — still open.**

Every other domain in §3 was checked against the same real map and holds with
room to spare: longest prefix text 42 (cap 49), largest ASN 4,020,790 (cap
33,521,664), smallest ASN 1, no `/0`, no `::ffff:` spelling. The full claim
replays end to end, `verify` passes, and the emitted map is byte-identical to
the input `.dat`.

The file-fed paths have no size bound whatsoever: `load_claims` (L348) does
`std::fs::read_to_string` on the whole file and deserializes every claim, so a
crafted `claims.json` is a straightforward OOM independent of any network cap.
This is deliberately **not** closed; §8.3 gives the reasoning, and §1 no longer
claims otherwise.

### 2.2 The `epoch` field has two incompatible interpretations

This is a pre-existing ambiguity that any bound must accommodate, so it is
recorded here rather than resolved silently:

- **As a Unix timestamp.** `scripts/README.md:63` and
  `scripts/test-publish-data.sh:28` both use `--epoch 1772726400`, and
  `docs/OPERATOR_GUIDE.md:22` has the coordinator publish the epoch before
  collection begins.
- **As a free-running counter.** `serve`/`collect` default to `epoch = 1` and do
  `engine.epoch() + 1` every `epoch_secs` (L1353, L1530).

`EPOCH_ABSOLUTE_MAX = 4_102_444_800` is chosen because it is a sane ceiling
under *both* readings — far above any plausible counter, and 2100-01-01 under the
timestamp reading. It is not a claim that the ambiguity is resolved. The relative
`MAX_EPOCH_SKEW` bound is the load-bearing one, and it should be generous enough
that a node offline for a normal outage still catches up in one hop.

`MAX_EPOCH_SKEW = 86_400` is that generous value: a day of seconds under the
timestamp reading, and 60x a day of 60-second `+1` ticks under the counter
reading.

The ceiling removes the `engine.epoch() + 1` overflow at L1353/L1530 — which
panics in debug and wraps to `0` in release/dist once `epoch` reaches
`u64::MAX` — for any epoch the engine can reach from a claim. Both sites were
additionally changed to `saturating_add(1)`, because the starting epoch is an
operator argument and nothing bounds *that*.

## 3. The table

Entry-level violations (`asn`, `ip_prefix` rows) **reject the entire claim**.
This is a deliberate change from current behaviour, which drops the offending
entry with a `warn!` and accepts the rest (L934-938). The current policy lets a
claim be 99% garbage and still be recorded `accepted: true`, consuming a
`threshold` slot while contributing almost no votes, with `rejected_claims` still
reading zero — an operator cannot distinguish a full claim from a hollowed-out
one. Fail-closed is the only policy under which the report means what it says.

Gate numbers below are the implemented ones in §4.3.

| Field | Type | Valid domain | Enforced at | Rejection reason |
| --- | --- | --- | --- | --- |
| Gossip envelope (`message.data`) | `Vec<u8>` | `len <= MAX_CLAIM_BYTES`; must deserialize as `AsmapClaim` | Transport, via explicit `max_transmit_size` (**NEW**, L762-765), plus `quorum_from_gossip`, which counts both failures instead of swallowing them in `if let Ok(..)` (**NEW**) | `oversize_claim`, `malformed_claim` |
| `AsmapClaim.sender_id` | `String` | `len <= MAX_SENDER_ID_LEN`, parses as `PeerId`, and equals `source.to_string()` | Gate 1 shape check (**NEW**); Gate 2 binding (existing, L886, **moved earlier**) | `invalid_sender_id`, `source_mismatch` |
| `AsmapClaim.claim_hash` | `String` | Exactly `CLAIM_HASH_LEN` lowercase hex chars; must equal `claim_hash(epoch, sender_id, entries)` | Gate 1 shape check (**NEW**); Gate 3 comparison (existing, L896) | `malformed_claim_hash`, `claim_hash_mismatch` |
| `AsmapClaim.entries` (length) | `Vec<AsmapEntry>` | `MIN_CLAIM_ENTRIES ..= MAX_CLAIM_ENTRIES` | Gate 1 shape check (**NEW**) | `empty_claim`, `too_many_entries` |
| `AsmapClaim.epoch` (ceiling) | `u64` | `<= limits.max_epoch` (`EPOCH_ABSOLUTE_MAX`, or the injected clock window) | Gate 1 shape check (**NEW**) | `epoch_out_of_range` |
| `AsmapClaim.epoch` (stale) | `u64` | `>= self.epoch` | Gate 4 (existing, L873, **moved after auth**) | `stale_epoch` |
| `AsmapClaim.epoch` (jump) | `u64` | `<= self.epoch.saturating_add(MAX_EPOCH_SKEW)` | Gate 5 (**NEW**, guards the epoch adoption at Gate 7) | `epoch_jump_too_large` |
| `AsmapEntry.asn` | `u32` | `1 ..= 33_521_664`; `0` is the ASMap unassigned sentinel and is never a claimable assignment | Gate 6, `validated_vote_keys` (**NEW**) | `asn_out_of_range`, `unassigned_asn` |
| `AsmapEntry.ip_prefix` (raw) | `String` | `len <= MAX_PREFIX_LEN` | Gate 6, before parsing (**NEW**) | `invalid_prefix` |
| `AsmapEntry.ip_prefix` (parse) | `String` | `ADDR/LEN`, `ADDR: IpAddr`, `LEN <= 32` (v4) / `<= 128` (v6) | `canonical_consensus_prefix` (existing, L384-396), called from Gate 6; **now rejects the claim** instead of `warn!`-and-drop | `invalid_prefix` |
| `AsmapEntry.ip_prefix` (family) | `String` | An IPv6 prefix must not **intersect** `::ffff:0:0/96` in either direction — neither at or below it (`::ffff:1.2.3.0/120` aliases v4 space and breaks the text↔trie bijection) nor above it (`::/1`, `::ffff:0:0/95`, which reassign v4 wholesale from a trie node no dotted quad can name) | Gate 6 (**NEW**; the *above* half added after review, §7) | `ipv4_mapped_prefix` |
| `AsmapEntry.ip_prefix` (length) | `u8` | `1 ..= 32` (v4) / `1 ..= 128` (v6): a `/0` in **either** family is that whole family in one entry | Gate 6 (**NEW**; the v4 half added after review, §7) | `default_route_prefix` |
| `AsmapEntry` (intra-claim) | `Vec<AsmapEntry>` | Each canonical prefix appears at most once. `(prefix, asn)` repeats are dropped; `(prefix, asn_a)` + `(prefix, asn_b)`, `a != b`, is self-contradictory | Gate 6, replacing the old `voted` set (existing, L921/L930, **now keyed on prefix alone**) | `conflicting_entry` |
| `QuorumEngine.seen_senders` (cap) | `HashSet<String>` | `len <= limits.max_senders` | Gate 8 (**NEW**, alongside dedupe at L906) | `sender_limit_exceeded` |
| `QuorumEngine.seen_senders` (dedupe) | `HashSet<String>` | Each `sender_id` claims at most once per epoch. One sender, one vote — otherwise `threshold` counts messages rather than participants | Gate 8 (existing, L906, **moved after adoption**) | `duplicate_sender` |
| `QuorumEngine.observations` | `Vec<ClaimObservation>` | Rejection observations `<= MAX_REJECTION_OBSERVATIONS`; accepted ones are already bounded by `max_senders` | `record_rejection` (**NEW**) | *(none — see below)* |
| `process_claim` sender parse | `String` | Parses as `PeerId` | `process_claim` — **records a rejection instead of returning silently** | `unparsable_sender` |

**The observation cap is not a rejection reason.** The originally specified
`observation_limit_reached` was dropped during implementation, because a reason
string in `rejected_claims` would have broken the reconciliation property in §6:
every claim must produce exactly one accounting event, so
`accepted_claims + sum(rejected_claims)` equals the number of claims processed.
A log-overflow marker is not a claim. Instead:

- accepted observations are never dropped (they are bounded by `max_senders`,
  and letting rejections crowd them out would hand an attacker a way to erase
  the record of the honest claims);
- rejection observations stop being retained past the cap, while
  `rejected_claims` keeps counting them, so no aggregate is lost;
- the overflow is derivable (retained rejections vs the counter sum), and the
  first drop emits a `warn!`.

Two rejections are counted but deliberately produce **no observation at all**:
`shape_violation` (Gate 1) and `source_mismatch` (Gate 2). Both are reachable
pre-authentication, and a `ClaimObservation` retains the sender's own string —
which is precisely the unbounded-growth vector §4.2 describes. The key-bounded
counter preserves the signal.

### 3.1 Notes on the subtle domains

**`ASN_MAX = 33_521_664` is a wire-format limit, not a policy choice.**
`CODER_ASN = VarLenCoder::new(1, &[15..=24])` (`crates/asmap-codec/src/coder.rs:222-223`).
`VarLenCoder::new` sets `maxval = minval + sum(1 << clsbits[i]) - 1`; the sum
over 2^15..2^24 is 2^25 - 2^15 = 33_521_664, so `maxval = 1 + 33_521_664 - 1`.
`4_261_445_631` of the 2^32 `u32` values cannot be encoded at all — including
every 32-bit ASN above 33.5M, and the whole IANA private-use range
`4_200_000_000..=4_294_967_294`. Values outside it reach
`assert!(self.can_encode(val))` at `coder.rs:76` during serialization, long
after the claim was accepted. **`assert!` is not compiled out in release, so
dist builds are equally affected.**

**`asn == 0` is a map-poisoning primitive, not a range error.** `TrieNode::Leaf(0)`
is ASMap's "unassigned" hole marker, so `0` is a legal trie value but must never
arrive as a claimed assignment. `update_multi` applies entries
shortest-prefix-first, so a more-specific AS0 entry punches a hole through a
covering assignment — and the result looks entirely legitimate in the report.

**IPv4-mapped IPv6 is an aliasing bug, not pedantry.** `ip_to_bits` maps IPv4
`a.b.c.d/L` to `(u32 + 0xffff_0000_0000, L + 96)` and IPv6 to `(u128, L)`.
So `1.2.3.0/24` and `::ffff:1.2.3.0/120` produce **byte-identical 120-bit trie
paths** while `canonical_consensus_prefix` renders them as two *different*
canonical strings. They are therefore distinct vote keys, which defeats the
`voted` set added specifically to stop one sender voting a network twice. Both
survive threshold; `finalize` pushes two `(bits, asn)` pairs with the same bit
path; `best_by_prefix` is a `HashMap` iterated under `RandomState`; `update_multi`
sorts stably by prefix length only. **Last writer wins, nondeterministically, per
process.** Rejecting the mapped range is one of two defensible fixes — the other
is normalizing it to dotted-quad form. Rejection is specified here because it is
simpler to test and no honest producer emits the mapped form
(`asmap_to_claim`, L1020, derives entries from `to_entries`).

**…and the range must be excluded from *above* as well as below.** The first
implementation tested `v6.to_ipv4_mapped().is_some()`, which is an exact-value
test where the hazard is a range. Because `ip_to_bits` gives every IPv4 path the
80-zero-bit prefix of `::ffff:0:0/96`, *any* IPv6 prefix whose bit path is a
prefix of that range covers the whole of IPv4 — `::/1`, `::/80`, and
`::ffff:0:0/95`, which host-masks to `::fffe:0:0/95` and whose
`to_ipv4_mapped()` is therefore `None`. Such a prefix sits at a trie node
strictly shallower than any dotted quad can express, so it reassigns IPv4 using
IPv6 syntax. The gate is now the symmetric one: **an IPv6 entry may not
intersect `::ffff:0:0/96` at all**, implemented as a bit-path comparison against
`IPV4_MAPPED_RANGE` for `prefix_len <= 96` and the original `to_ipv4_mapped()`
test below it.

**`/0` is excluded from the consensus domain in both families.** A real ASMap
never assigns the default route. For IPv6 the bit path is empty and
`ASMap::update` replaces the whole trie root. For IPv4 an earlier draft of this
document called `0.0.0.0/0` harmless "because `ip_to_bits` still emits 96 bits
for the v4-mapped range" — that is correct about the trie root and wrong about
the consequence, since those 96 bits *are* the whole of IPv4. `0.0.0.0/0` passed
every gate, reached the artifact at threshold with an empty rejection ledger, and
`decode` printed it back as `0.0.0.0/0 AS666` while the byte-identical trie path
spelled `::ffff:0:0/96` was rejected. Both spellings are now rejected.

**The entry gates reject a *range*, never a prefix length — and must not be
tightened into one.** The obvious-looking generalisation ("require at least a
/8") would reject honest production data. Measured over all 29 snapshots in
`data/`: the flat non-overlapping form that `asmap_to_claim` actually emits
bottoms out at `224.0.0.0/3` and `1000::/4`, and the overlapping text form of
`data/latest_asmap.dat` opens with `::/2 AS16509` and `0.0.0.0/3 AS749`. The
same measurement is what licenses the two gates above: across those 29 snapshots
there is **not one** entry at `/0`, and **not one** IPv6 entry that intersects
`::ffff:0:0/96`. Consequently `8000::/1` — one bit from the rejected `::/1` — is
**accepted**, because nothing distinguishes it from `224.0.0.0/3` except which
half of the space it names, and it cannot reach IPv4 at all. Bounding how much
space a *legitimately shaped* prefix may claim is a quorum-policy question, not
an input-validation one; see §8. `a_well_formed_claim_is_still_accepted_whole`
and `the_shortest_prefixes_real_snapshots_contain_are_still_accepted` are the
tests that will break first if anyone tries the prefix-length rule.

**A broad prefix does not displace a more specific one.** Worth stating because
the review reproductions showed "every IPv4 address now resolves to AS666" from
a *one-entry* map. The trie keeps the deeper leaf: `0.0.0.0/0 AS666` alongside
`8.8.8.0/24 AS15169` still resolves `8.8.8.8` to AS15169. The damage from an
over-broad entry is the residual space a real map leaves uncovered — large, and
worth rejecting, but not the whole internet.

**Host-bit masking is kept as-is.** PR #7's `canonical_consensus_prefix` masks
host bits rather than rejecting, so v0.0.8 artifacts stay loadable. That policy
is sound and this PR does not change it.

## 4. Gate ordering

### The invariant

> **No shared engine state is mutated before authenticity is established.**

Concretely: `self.epoch`, `self.seen_senders`, `self.votes`,
`self.observations`, `self.accepted_claims` and `self.rejected_claims` are
untouched until the claim has passed Gate 2. Gate 1 is a pure predicate over the
claim alone. The ordering principle is:

> pure predicates → authenticity binding → integrity → epoch → dedupe → tally.

A corollary worth stating separately, because it is the cheaper half of the fix:
**expensive work must not precede cheap rejections.** `claim_hash()` (L872)
deep-clones the entry vector, sorts it `O(n log n)` with string comparisons,
formats every entry into a buffer and SHA-256s the result — all *before* the
cheapest gate. Today the least expensive rejection is the most expensive to
reach, at roughly 3× the message size in transient allocation, for a claim
discarded one line later.

### 4.1 Current order (defective)

1. **L870-871** — bind locals. No gate, no mutation.
2. **L872** — compute `expected_hash`. Unbounded attacker-driven CPU and
   allocation, before any gate.
3. **L873-882** — Gate: `epoch < self.epoch` → `record_rejection("stale_epoch")`.
   **Mutates `observations` + `rejected_claims`.**
4. **L883-885** — `epoch > self.epoch` → `advance_epoch(claim.epoch)`.
   **Destroys all accumulated state.** Not a validation gate at all: an
   unconditional state transition keyed on untrusted JSON.
5. **L886-895** — Gate: `sender_id != source_peer_id` → `source_mismatch`.
   **The only authenticity check, and it is fourth.**
6. **L896-905** — Gate: `claim_hash != expected_hash` → `claim_hash_mismatch`.
7. **L906-915** — Gate: `seen_senders.insert` → `duplicate_sender`.
8. **L920-940** — vote accumulation. **L941-949** — observation push, counter.
9. **L950** — return `seen_senders.len() >= threshold`.

### 4.2 Why this is the headline defect

`advance_epoch` (L832-839) sets `self.epoch` to an attacker-chosen `u64` and
clears `seen_senders`, `votes`, `observations`, `accepted_claims` and
`rejected_claims`. It runs at step 4 — **before** the source binding at step 5
and the hash check at step 6. A claim that is rejected moments later has already
wiped the round.

Reproduced on the **offline path**, no network required. A `claims.json` of four
records — two honest accepted claims at epoch 1, then one claim at
`epoch: 18446744073709551615` **carrying a deliberately wrong `claim_hash`**,
then one more honest claim — replayed at `--threshold 2`:

```
$ asmap-quorum replay --threshold 2 --output h.bin --report h.json c5.json
[INFO asmap::replay] replayed 2 claims (0 accepted) into h.bin and h.json

epoch:        18446744073709551615
accepted:     0
rejected:     {'claim_hash_mismatch': 1, 'stale_epoch': 1}
entries:      0
observations: 2
```

Every element of that output is a defect:

- The two honest claims that had already been **accepted** are gone.
- The claim that erased them was itself **rejected** (`claim_hash_mismatch`) —
  it never passed a single gate, and it still moved the engine.
- `epoch` is pinned at `u64::MAX`, so every subsequent honest claim is
  `stale_epoch` **forever**.
- The report says "replayed 2 claims" for a 4-claim input; the accepted
  observations were cleared along with everything else, so the audit trail of
  the attack is destroyed by the attack.
- An artifact was still written — an empty map, silently.

On the gossip path the same message arrives from any connected peer with no
allowlist and no signature, and two effects compound it: the `serve` loop
re-stamps its own outgoing claim with `engine.epoch()` (L1347-1348), so a
poisoned node **republishes the poison** and drags the mesh forward; and
`consensus_written` is reset only by the epoch timer (L1357), never by a
gossip-driven advance, so a node bumped mid-epoch will not emit an artifact for
the new epoch even if quorum is later reached.

The bound on `epoch` and the reordering are **separate fixes and both are
required**. A bound alone still lets any peer reset the tally within the bound;
reordering alone still lets an authenticated peer jump to `u64::MAX`.

### 4.3 Implemented order

| # | Gate | Checks | State touched |
| --- | --- | --- | --- |
| 1 | **Shape** (NEW) | `sender_id.len()`; `claim_hash.len() == 64` and lowercase hex; `entries.len()` in range; `epoch <= limits.max_epoch` | **None** but the key-bounded reason counter. Pure predicate — the only checks possible before we know who is speaking |
| 2 | **Authenticity** (moved up from L886) | `sender_id == source_peer_id` | Bounded counter only; no `observations` push |
| 3 | **Integrity** (moved down from L872/L896) | compute `expected_hash` *here*, then compare | `record_rejection` — now reachable only by an authenticated identity |
| 4 | **Epoch, stale** | `epoch < self.epoch` | `record_rejection` |
| 5 | **Epoch, jump** | `epoch > self.epoch.saturating_add(MAX_EPOCH_SKEW)` → reject | `record_rejection` |
| 6 | **Entries** | per-entry domain checks (§3); any violation rejects the claim. Returns the deduplicated vote keys | `record_rejection` |
| 7 | **Epoch adoption** | `epoch > self.epoch` → adopt | `epoch`, and the clears that go with it |
| 8 | **Sender cap / dedupe** | `seen_senders.len() < limits.max_senders`; `seen_senders.insert` | `seen_senders` |
| 9 | **Tally** | `votes` increment, observation push, counter | `votes`, `observations`, `accepted_claims` |

**One deliberate deviation from §4.3 as first written**, in the direction of a
stronger invariant. Entry validation was specified *after* the epoch advance;
it is implemented *before* it (Gate 6 ahead of Gate 7). The reason is that with
the entry checks in front, no rejection path remains behind the adoption point:
Gates 8's two branches are unreachable on a claim that just advanced the epoch,
because adoption clears `seen_senders`. That upgrades the invariant from

> no shared state is mutated before *authenticity*

to the strictly stronger, and much more testable

> **a rejected claim never mutates `epoch`, `seen_senders` or `votes` at all** —
> whatever it is rejected for.

That is what `rejected_claims_never_mutate_engine_state` pins. The cost is one
attribution difference: a claim that is both stale *and* carries a bad entry
still reports `stale_epoch`, since Gate 4 is cheap and stays ahead of the
per-entry work, but a *future* claim with a bad entry now reports the entry
reason rather than silently moving the engine first.

Two payload fixes went with the reorder: `record_rejection` passed `self.epoch`
(L874) and the locally recomputed `expected_hash` rather than what was received,
so the observation log **silently lost what the attacker actually asserted**. It
now records `claim.epoch` and `claim.claim_hash`.

### 4.3.1 The epoch bound is injected, never read from the clock in the tally

`ClaimLimits` carries `max_epoch` and `max_epoch_skew` and is passed to
`QuorumEngine::with_limits`. Three consequences worth stating:

- `ClaimLimits::at_unix_time(now)` takes the timestamp as an **argument**;
  `QuorumEngine::new` is the only caller that reads the clock, via
  `current_unix_time()`. The gates themselves are a pure function of the claim
  and the limits.
- `replay` uses `ClaimLimits::default()` — the absolute ceiling, no clock.
  Deriving the ceiling from the wall clock there would make the artifact depend
  on *when* the replay ran, and `docs/OPERATOR_GUIDE.md:119` has independent
  operators attest SHA256SUMS over exactly those bytes.
- Only `advance_epoch` — the *local*, operator-or-timer-driven path — may raise
  the ceiling. A claim-driven adoption never does, or the ceiling would become a
  ratchet an attacker walks upward one `max_epoch_skew` at a time. Raising it
  locally is what keeps a long-lived node, whose own counter walks past its
  starting ceiling, able to accept honest claims.
- **Every raise is capped at `EPOCH_ABSOLUTE_MAX`,** in both
  `QuorumEngine::with_limits` and `advance_epoch`. Without the cap the previous
  bullet was defeated by *composition*, which review demonstrated twice:
  - `run_replay` seeds the engine from `claims[0].epoch` when `--epoch` is
    omitted, and `with_limits` then widened `max_epoch` to
    `epoch + max_epoch_skew`. Both values came from attacker JSON, so a first
    record carrying `u64::MAX` made Gate 1 unfirable, pinned the engine there,
    and every honest claim behind it was rejected `stale_epoch` — reproducing
    the §4.2 defect by *file order alone*. `replay` now bails when the starting
    epoch, from either source, is above the ceiling.
  - `serve` and `collect` call `advance_epoch(engine.epoch() + 1)` on each timer
    tick, and `engine.epoch()` is claim-influenced. One attacker claim per tick
    therefore lifted the ceiling by `max_epoch_skew` per tick, past
    `EPOCH_ABSOLUTE_MAX`, without bound. With the cap the ceiling saturates
    exactly at `EPOCH_ABSOLUTE_MAX`
    (`the_serve_timer_cannot_ratchet_the_ceiling_past_the_absolute_maximum`).

  The cap bounds the widening; it never *lowers* a ceiling a caller asked for,
  so `ClaimLimits { max_epoch: EPOCH_ABSOLUTE_MAX + n, .. }` is preserved.
- **`max_senders` is widened to at least one,** not merely to `threshold`. At
  zero — reachable as `with_limits(0, _, ClaimLimits { max_senders: 0, .. })` —
  Gate 8's cap branch evaluated `0 >= 0` against the set Gate 7 had just cleared
  and rejected a claim that had *already moved the epoch*, which is the one
  counterexample review found to the §4.3 invariant. Library API only; no CLI
  path could reach it.

### 4.4 Which reorderings are behaviour-preserving

Stated explicitly so review can check each independently:

**Safe — no claim accepted today becomes rejected.** Moving the authenticity
compare (L886) above both epoch gates. An honest directly-connected peer always
satisfies it; an honest relayed claim already fails today, just later, after
being allowed to move the epoch.

**Safe — no change to the accepted set.** Moving the hash check above the epoch
gates and the hash *computation* down to meet it. The only visible difference is
reason attribution for a claim that is both stale and hash-broken: it now reports
`claim_hash_mismatch` rather than `stale_epoch`. Nothing in the repository
asserts on these strings — `grep` finds no test, script or fixture depending on
any of the four current reason values.

**Deliberate behaviour changes, each needing a release note.** All five are
implemented as described.
(a) Suppressing the `observations` push for `source_mismatch` (and for every
Gate 1 shape rejection) drops those rows from the report — that is the point,
since it is the unbounded vector; the key-bounded `rejected_claims` counter
preserves the signal.
(b) `MAX_EPOCH_SKEW` means a node offline longer than the bound no longer
catches up in one hop.
(c) Entry-level violations now reject the whole claim rather than dropping the
entry (§3). This is the only change that required editing an existing test:
`unparseable_claim_prefix_never_reaches_the_artifact` asserted the old
drop-and-accept policy, and is now
`claim_validation_rejects_invalid_prefix`.
(d) `MAX_CLAIM_ENTRIES` will reject oversized claims. Sized from the
measurement in §2.1, it does not reject any honest claim this repository can
produce.
(e) `replay` now logs `replayed N claims (A accepted, R rejected)` counted from
the input, not `observations.len()`, which was never a claim counter: an epoch
advance mid-file clears the log.

**Four further behaviour changes, added after review. Each needs a release
note.** The first two are exit-status changes on `replay`; the last two were
already implemented but were missing from this list, which is the omission
review flagged.

(f) **`replay` exits non-zero when the consensus map is empty**, after writing
both the map and the report. Previously it exited 0, and `verify` passes on a
zero-byte map because such a map is internally consistent — so a
`--epoch` argument stale by more than `MAX_EPOCH_SKEW` against the claims file
rejected every claim `epoch_jump_too_large`, and `scripts/_release_round.sh`
walked the resulting empty map through `replayed → verified → attested →
published` without a murmur. This is not hypothetical: the documented workflow
reads `epoch` as a Unix timestamp (`scripts/README.md:63`,
`scripts/test-publish-data.sh:28`) and `docs/OPERATOR_GUIDE.md` has operators
bump it per round, so consecutive rounds are weeks or months apart — far outside
a 24-hour skew window. An empty map is never a releasable artifact, whether the
cause is a wrong `--epoch`, an all-hostile file, or genuine disagreement below
`threshold`; the error names the rejection breakdown so the operator can tell
which. The map and report are still written first, deliberately, because that
breakdown is the diagnostic. Two existing tests moved from `expect_success` to
`expect_failure` for this reason and kept every one of their report assertions.

(g) **`replay` exits non-zero when the starting epoch is above
`EPOCH_ABSOLUTE_MAX`,** whether it came from `--epoch` or from
`claims[0].epoch`. See §4.3.1.

(h) `MIN_CLAIM_ENTRIES = 1` means a **zero-entry claim no longer consumes a
`threshold` slot**: it is rejected `empty_claim` rather than accepted. The
pipeline can legitimately produce one — `import` on an empty snapshot yields a
well-formed claim with a correct `claim_hash` and no entries, e.g. when an
operator's RIS bottleneck extraction came back empty. That changes the
participant count for input the tooling itself emits, which is why it belongs on
this list. It is nonetheless the right policy: an empty claim carries no
information, and letting it count toward `threshold` lets a peer reach quorum
while asserting nothing.

(i) A node left at `serve`'s documented default `epoch 1` (`README.md:232`) can
**no longer join a mesh running timestamp epochs**, because the first honest
claim it hears is now `epoch_jump_too_large` rather than a one-hop catch-up.
Counter-mode catch-up is unaffected and has 86,400 ticks × 60s ≈ 60 days of
headroom; verified identical to the base branch (engine at epoch 1, claims at
epoch 5, byte-identical artifacts). This is the pre-existing `epoch` ambiguity of
§2.2 becoming load-bearing. The supported path is fine —
`docs/OPERATOR_GUIDE.md:22` tells operators to wait for the coordinator's epoch
and `scripts/test-human-quorum.sh:89` passes it explicitly — so this is recorded
rather than fixed; fixing it properly means resolving §2.2.

**Must not be removed:** `advance_epoch` as a response to a peer claim. `epoch`
is a free-running local counter with no wall-clock anchor, so gossip-driven
catch-up is the only mechanism by which a late-joining node synchronises. **Gate
it, do not delete it.** If a stronger property is wanted, require *K* distinct
authenticated senders to assert a new epoch before adopting it, so no single
identity can reset the tally; that is a strict improvement over `MAX_EPOCH_SKEW`
and is compatible with this ordering.

## 5. Deliberately not validated here

**Claim authenticity in any real sense.** Claims carry no signatures. This PR
does not add them. Gate 2 verifies only that the transport source matches the
declared `sender_id`, which any freshly minted PeerId satisfies by construction.
See §1.

**Sybil resistance / participant admission.** `MAX_SENDERS` bounds *memory*, not
*trust* — it caps how many identities may be admitted, not which. One host can
still mint identities up to that cap and reach `threshold` alone. Fixing this
requires an operator roster or signed claims, i.e. a settled identity model, and
that decision should not be made incidentally inside a bounds-checking PR.

**Whether a claim is *true*.** Nothing here checks a claimed `prefix -> ASN`
against reality. That is what the threshold is for, and the threshold is only as
good as the identity model above.

**The `propagation_source` / `message.source` confusion.** `serve` (L1384-1392)
and `collect` (L1583-1591) pass gossipsub's `propagation_source` — the
*forwarding neighbour* — as the claim's source, not the signature-verified
`message.source` (available, since the swarm uses `MessageAuthenticity::Signed`).
So **a legitimately relayed honest claim is rejected as `source_mismatch` while a
directly-connected Sybil is accepted**: the check authenticates the wrong hop.
This also means `observations` grows at gossip-message rate in *normal* mesh
operation, not only under attack. This is a genuine defect and arguably belongs
in this PR, but it changes which claims are accepted in a multi-hop mesh and
wants its own testing against a real relay topology. **Recorded here, not fixed
here.**

**`consensus_written` not being reset by `advance_epoch`** (L1341/L1357). A
real bug, surfaced by §4.2, but it lives in the serve/collect loops rather than
the ingest path.

**Codec-layer hardening.** Per this PR's constraints, `crates/asmap-codec` is not
modified. One observation is reported rather than fixed:
`VarLenCoder::encode_size` (`coder.rs:57`) computes `val - self.minval`, which
underflows for `val == 0`. It appears unreachable today because
`TrieNode::Leaf(0)` always sets `hole = true` and the `if !hole` guard suppresses
`Default`-node construction — but nothing *enforces* that invariant. Rejecting
`asn == 0` at ingest closes the path from the network side regardless, so **no
codec change is required for this specification.** The `assert!` at `coder.rs:76`
is likewise left alone: making the ingest layer never feed it an out-of-range
value is the fix specified here, but converting that assert into a `Result`
remains worthwhile defence in depth for a future codec PR.

## 6. Test requirements

**Every row in the table in §3 must have at least one test that fails without
the corresponding check.** A row with no failing-without-the-fix test is not
considered implemented.

Where they live:

| Kind | Location |
| --- | --- |
| Gate unit tests, one per rejection reason | `crates/bitcoin-asmap-quorum/src/lib.rs`, `mod tests` (L2367) |
| Per-row domain matrix, library level | `crates/bitcoin-asmap-quorum/tests/claim_validation_matrix.rs` |
| Quorum behaviour under disagreement | `crates/bitcoin-asmap-quorum/tests/quorum_disagreement.rs` |
| Attacks tried against the gates, and what each does today | `crates/bitcoin-asmap-quorum/tests/adversarial_bounds.rs` |
| CLI-level rejection and exit-code tests | `crates/bitcoin-asmap-quorum/tests/cli_negative.rs` |
| End-to-end quorum behaviour | `crates/bitcoin-asmap-quorum/tests/consensus_lifecycle.rs` |
| Cross-checks against the Python reference | `crates/bitcoin-asmap-quorum/tests/differential_python.rs` |

`adversarial_bounds.rs` deserves a note on how to read it, because it began life
during review as `bypass_hunt.rs` — a suite whose header declared that *every
passing test is a defect*. That polarity inverts the meaning of a green CI run
and must not come back. Every test in it now asserts the behaviour that is
wanted. The attacks that are still open are prefixed `known_open_` and pin
today's behaviour deliberately, so that changing the policy in §8 produces a
failing test that says so, rather than silent drift. Each closed attack is paired
with the honest input that must keep working, so no future fix can take the shape
of "reject more".

Naming convention: `claim_validation_rejects_<reason>`, one per reason string, so
the test name and the report field match.

Required coverage beyond the per-row tests, all three implemented:

1. **Ordering, not just outcome.** `rejected_claims_never_mutate_engine_state`
   builds the §4.2 scenario — two accepted claims, then a hostile one — and
   asserts `epoch`, `votes`, `seen_senders` and `accepted_claims` are unchanged
   after each of three rejection shapes (past the ceiling, hash-broken, and
   hash-valid with an out-of-domain entry). Per-row rejection tests pass even
   with the gates in the wrong order; only this one pins the invariant.
2. **Determinism.** `consensus_output_is_byte_identical_across_runs` (unit) and
   `cli_replay_of_ipv4_mapped_alias_is_rejected_and_deterministic` (CLI, 10
   runs, each followed by `verify`). The IPv4-mapped case failed this on roughly
   half of runs before the fix (§7).
3. **Reconciliation.** `every_claim_is_accounted_for_exactly_once` asserts
   `accepted_claims + sum(rejected_claims) == input count` over a mixed batch,
   so the silent-drop paths cannot regress. Note this is the *counter* identity,
   not an `observations.len()` identity — see the retention policy in §3.

The reproduced defects in §7 also have CLI-level regression tests in
`tests/cli_negative.rs`: `cli_replay_rejects_out_of_cap_asn_instead_of_aborting`
(the process abort), `cli_replay_rejects_default_route_takeover` (now covering
both `::/0` and `0.0.0.0/0`),
`cli_replay_rejects_ipv6_prefixes_that_swallow_the_mapped_range`,
`cli_replay_rejects_an_out_of_range_epoch_seeded_from_the_file`, the determinism
test above, and — as the counterweight to all of them —
`cli_replay_still_accepts_the_shortest_real_world_prefixes`.

4. **No behaviour change for well-formed input.** Not a test in the suite but a
   release gate, re-run for every change to this layer: build the base branch
   and this one, and compare artifacts byte-for-byte. Current evidence — real
   three-operator claims imported from `data/2026/{1772726400,1776960000,1780588800}_asmap.dat`
   (741,964-entry claims) replayed at thresholds 1, 2 and 3; a four-operator
   2-vs-2 tie-break at thresholds 1-4; a legitimate mid-file epoch advance; and
   counter-mode catch-up from epoch 1 to epoch 5. Map and report were
   byte-identical in every case, including the 1,582,731-byte and
   1,548,489-byte real-data artifacts. The only differences anywhere are exit
   statuses where the artifact was *empty* — item (f) in §4.4 — and in those
   cases the bytes still matched.

### 6.1 Two existing tests were vacuous and are fixed

`quorum_engine_dedupes_sender` (L2892) and `quorum_engine_rejects_stale_epochs`
(L2948) both build claims with `sender_id: "peer-a"`. That is not valid base58,
so it fails the `PeerId` parse at L862 and returns `false` at L863 — **neither
test ever reaches the gate it is named for.** `quorum_engine_rejects_stale_epochs`
then asserts `engine.epoch() == 7`, which holds trivially.

Confirmed by feeding a `"peer-a"` claim with a *correct* hash through `replay`:

```
[INFO asmap::replay] replayed 0 claims (0 accepted)
accepted: 0  rejected: {}  observations: 0
```

Zero observations, zero rejections — a completely silent drop. This
simultaneously demonstrates the `unparsable_sender` row in §3 and proves both
tests are vacuous. The dedupe and stale-epoch paths were therefore effectively
untested, and this PR reorders both. Both now use `PeerId::random().to_string()`
like the neighbouring tests, and each additionally asserts the reason counter,
so they fail if the gate they are named for stops firing.

## 7. Reproductions

All were re-run with scratch files outside the repository — the first four
against `91b6ba2`, the last three against the `claim-validation` branch itself
during review, which is why they are defects this document previously claimed to
have closed. The §4.2 epoch reproduction and the §6.1 silent drop are listed
above; these are the map-corruption cases.

**ASN above the codec cap — remote panic.** `import` a one-line map
`1.2.3.0/24 AS4200000000`, then `replay --threshold 1`:

```
thread 'main' panicked at crates/asmap-codec/src/coder.rs:76:9:
assertion failed: self.can_encode(val)
```

The node aborts the instant quorum is reached, at `save_binary` (L1396 serve /
L1595 collect / L2294 replay). Release builds too — `assert!` survives.

**`::/0` single-entry takeover.** One entry `{"ip_prefix":"::/0","asn":666}`
produces a map that `decode` prints in full as:

```
::/0 AS666
```

Every IPv4 and IPv6 address resolves to the attacker's ASN, from one entry, with
no volume. `verify` **exits 0** — the report's self-consistency check offers no
protection. For a map whose only purpose is peer-bucketing diversity, this
collapses all diversity to a single bucket.

**`0.0.0.0/0` — the same takeover, restricted to IPv4, which survived the first
fix.** Found by review against the branch that had already shipped the `::/0`
gate. Two senders, correctly hashed, `--threshold 2 --epoch 7`:

```
$ bitcoin-asmap-quorum replay --threshold 2 --epoch 7 ... claims.json
  replayed 2 claims (2 accepted, 0 rejected)
  report: rejected_claims {}, entries [{0.0.0.0/0, AS666, votes 2}]
$ bitcoin-asmap-quorum decode consensus.dat
0.0.0.0/0 AS666
$ bitcoin-asmap-quorum verify report.json consensus.dat ; echo $?
0
```

The identical trie path spelled `::ffff:0:0/96` was rejected `ipv4_mapped_prefix`
in the same build, which is what made this a gap in the rule's letter rather
than in its intent. Two neighbouring spellings behaved the same way: `::/1`
(and `::/80`, and anything else all-zero) and `::ffff:0:0/95`, which host-masks
to `::fffe:0:0/95` so `to_ipv4_mapped()` returns `None`. All are now rejected;
see §3.1 for the rule and for the measurement that says why it is a range test
and not a prefix-length test.

**Epoch ceiling defeated by claims-file order.** Also found by review. A
three-record file `[hostile epoch=u64::MAX, honest epoch=1, honest epoch=1]`
replayed with `--threshold 2` and **no `--epoch`**:

```
report: epoch 18446744073709551615, accepted_claims 0,
        rejected_claims {stale_epoch: 2}, entries []
```

— element for element the §4.2 output this PR exists to prevent, reached by
reordering a file. The same three records with the hostile one *last* reached
consensus normally. `run_replay` seeded the engine from `claims[0].epoch` and
`with_limits` widened `max_epoch` to match, so Gate 1 could not fire; the gate
ordering was correct all along and simply was not on the path that chose the
epoch. Fixed per §4.3.1, with
`cli_replay_rejects_an_out_of_range_epoch_seeded_from_the_file` pinning both
halves — the rejection *and* the reordered control that must still succeed.

**AS0 hole-punch.** A claim of `1.0.0.0/8 -> AS100` plus `1.2.3.0/24 -> AS0`
yields a map in which the covering /8 has been shredded into 16 fragments
(`1.0.0.0/15`, `1.2.0.0/23`, `1.2.2.0/24`, `1.2.4.0/22`, … `1.128.0.0/9`) and
`1.2.3.0/24` is unassigned. `verify` **exits 0**: the corruption is invisible to
the tool's own integrity check.

**IPv4-mapped alias — nondeterministic output.** One threshold-1 claim carrying
both `1.2.3.0/24 -> AS100` and `::ffff:1.2.3.0/120 -> AS200`. Ten identical
replay runs of the identical input file:

| Runs | Output map (sha256 prefix) | Decodes to | `verify` |
| --- | --- | --- | --- |
| 6 | `0543ec9b20c9` | `1.2.3.0/24 AS100` | **exit 1** |
| 4 | `a9b3e0b9843a` | `1.2.3.0/24 AS200` | exit 0 |

Two different consensus artifacts from one input, and on the majority of runs
**the tool's own `verify` rejects the artifact it just wrote** ("binary/text map
does not match the report artifact"). This is the finding that matters most for
the project's actual purpose: byte-reproducibility across independent operators
replaying identical claims is the property the whole attestation workflow rests
on.

## 8. Known open, and why each is out of scope here

This PR bounds what a *claim* may contain and when it may move the engine. Two
classes of problem sit outside that boundary. Both were demonstrated during
review, neither is fixed here, and both are pinned by tests so that changing
them is a deliberate act.

### 8.1 Epoch advancement is unauthenticated (consensus policy)

Gate 7 adopts a new epoch on the authority of **one** claim, and
`reset_for_epoch` clears `seen_senders` *before* Gate 8 can notice a repeat.
Nothing rate-limits advancement per identity. Two consequences, both reproduced
in `tests/adversarial_bounds.rs`:

- `known_open_one_identity_can_walk_the_epoch_to_the_absolute_ceiling`: one
  PeerId reaches `EPOCH_ABSOLUTE_MAX` from a settled threshold-2 engine in
  roughly 47,000 accepted claims — about 10 MB of gossip — erasing the honest
  round and making every honest claim `stale_epoch` thereafter.
- `known_open_one_identity_can_reset_the_tally_every_round`: the cheap form.
  One `+1` epoch claim per round, from a single identity, wipes the accumulated
  tally every time. Every such claim is **accepted**, so the §4.3 invariant
  ("a rejected claim never mutates state") does not constrain it at all — which
  is the honest reason that invariant is not a sufficient answer here.

What this PR did change is the *bound*: `MAX_EPOCH_SKEW` turns a one-packet
reset into a ~47,000-packet one, and the `EPOCH_ABSOLUTE_MAX` cap in §4.3.1
means the walk terminates instead of ratcheting forever. That is a mitigation,
not a fix.

The fix is the K-distinct-senders rule already sketched in §4.4: require *K*
authenticated senders to assert a new epoch before adopting it. It is out of
scope here because it changes **what `finalize` emits for well-formed input** —
a legitimate mid-file epoch advance in `replay` is driven by exactly one claim
today, and every artifact in the §6 byte-comparison depends on that — so it is a
consensus-semantics decision for the maintainer, not an input-validation change.

### 8.2 How much space one legitimately shaped prefix may claim

`8000::/1` is accepted. So is `0.0.0.0/1`. The measurement in §3.1 shows why no
prefix-length rule can reject them without also rejecting `224.0.0.0/3` and
`1000::/4`, which occur in every shipped snapshot. Bounding the *coverage* of an
accepted entry — as opposed to rejecting the two ranges that are structurally
unreachable from honest tooling — needs a policy input this layer does not have:
either an address-count budget per claim, or the identity model of §5, since
reaching `threshold` at all already requires threshold-many colluding senders.
Recorded here so that the acceptance is a decision rather than an oversight.

### 8.3 Smaller items, recorded rather than fixed

- **No byte cap on the `replay` claims file** (§1, §2.1). `replay` is an offline
  operator tool reading a file the operator chose, and the honest input is
  genuinely large — a single full-map claim is ~58 MB of JSON, so any cap
  generous enough for a real multi-operator round bounds nothing an attacker
  cares about while adding a new way for a legitimate round to fail. The
  network path, which is the attacker-controlled one, is capped twice at
  `MAX_CLAIM_BYTES` (gossipsub `max_transmit_size`, and again on receipt).
- **`Cargo.lock` is untracked and not ignored.** A binary-producing workspace
  normally commits its lockfile, and this one has `docs/OPERATOR_GUIDE.md`
  resting on byte-reproducible replay artifacts, which makes the dependency set
  load-bearing. It shows as `??` in every `git status` and would be swept in by
  an `git add -A`. Pre-existing; needs a maintainer decision, not a code change.
- **Relayed claims no longer drag a laggard node's epoch forward.** On a
  gossipsub mesh `propagation_source` is the forwarding peer, so a relayed claim
  fails the Gate 2 binding on both branches — the accepted set is unchanged.
  What is gone is the side effect: the old order advanced the epoch *before* the
  source check, so a relayed claim bumped the receiver's epoch on its way to
  being rejected. Removing that is the point of the PR (it was the one-packet
  reset primitive), but multi-hop topologies now depend solely on each node's
  own `epoch_secs` timer for alignment. Full-mesh and circuit-relay deployments
  (`scripts/test-human-quorum.sh`) are unaffected, because the direct peer is
  the publisher.
