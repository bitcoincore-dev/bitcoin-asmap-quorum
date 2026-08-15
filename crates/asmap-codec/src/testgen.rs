//! Deterministic random [`ASMap`] generation for tests.
//!
//! Behind the off-by-default `testgen` feature. It exists so the property and
//! differential tests can build reproducible corpora from a single `u64` seed
//! without pulling `proptest`/`quickcheck` into a crate that downstream
//! consumers may want to vendor.
//!
//! Shrinking is deliberately absent: a "smaller" random trie is not a simpler
//! counterexample in any useful sense, and a seed plus the three generation
//! parameters already reproduces a failure exactly.

use crate::net::ASNEntry;
use crate::trie::ASMap;

/// SplitMix64 — Steele et al., "Fast Splittable Pseudorandom Number
/// Generators" (OOPSLA 2014). Chosen for being twenty lines, seedable from any
/// `u64` including zero, and identical on every platform.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

/// The SplitMix64 finalizer, usable standalone as a seed-mixing function.
///
/// Used to turn `(master_seed, trial_index)` into a per-trial seed so that a
/// trial is a pure function of its own index and does not depend on how many
/// trials ran before it.
pub fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl SplitMix64 {
    /// Seeds the generator.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a value in `0..n`. Panics if `n` is zero.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "below(0) has no valid result");
        // Lemire's debiased multiply-shift rejection method.
        let mut m = (self.next_u64() as u128) * (n as u128);
        let mut low = m as u64;
        if low < n {
            let threshold = n.wrapping_neg() % n;
            while low < threshold {
                m = (self.next_u64() as u128) * (n as u128);
                low = m as u64;
            }
        }
        (m >> 64) as u64
    }

    /// Returns a value in `min..max`. Panics unless `min < max`.
    pub fn range(&mut self, min: u64, max: u64) -> u64 {
        assert!(min < max, "range({min}, {max}) is empty");
        min + self.below(max - min)
    }

    /// Returns a `f64` uniform over `[0, 1)`, using 53 bits of entropy.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / 9_007_199_254_740_992.0)
    }
}

/// The three knobs of [`random_map`], bundled so the differential test can send
/// the identical values to the Python oracle.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RandomMapParams {
    /// Requested number of trie leaves, at least 1. The realised count may be
    /// lower, because adjacent leaves that draw the same ASN merge.
    pub num_leaves: u32,
    /// Largest ASN that may be drawn, at least 1.
    pub max_asn: u32,
    /// Probability that a leaf is left unassigned (AS0).
    pub unassigned_prob: f64,
}

impl RandomMapParams {
    /// Draws generation parameters matching the distribution the original
    /// `fuzz.py` measurement used: `num_leaves` and `max_asn` uniform over
    /// `1..40`, `unassigned_prob` drawn from `{0.0, 0.3, 0.5}`.
    pub fn draw(rng: &mut SplitMix64) -> Self {
        const PROBS: [f64; 3] = [0.0, 0.3, 0.5];
        Self {
            num_leaves: rng.range(1, 40) as u32,
            max_asn: rng.range(1, 40) as u32,
            unassigned_prob: PROBS[rng.below(PROBS.len() as u64) as usize],
        }
    }
}

/// Builds a random [`ASMap`] — a port of `ASMap.from_random` in
/// `contrib/asmap/asmap.py`.
///
/// The Python grows a trie by repeatedly splitting a uniformly chosen leaf,
/// then draws an ASN (or AS0) for each resulting leaf. This tracks each leaf by
/// its prefix bit path instead of by node identity, so it can build the map
/// through the crate's public [`ASMap::update_multi`] rather than reaching into
/// the trie. The two agree because `update_multi` merges equal sibling leaves
/// on the way back up, which is precisely what the Python's `_set_trie`
/// normalisation does.
///
/// This does **not** reproduce Python's Mersenne Twister stream, so a given
/// seed yields different maps here and there. That is intentional: the
/// differential test takes its maps from the oracle and never needs the two
/// generators to agree.
pub fn random_map(rng: &mut SplitMix64, params: RandomMapParams) -> ASMap {
    assert!(params.num_leaves >= 1);
    assert!(params.max_asn >= 1 || params.unassigned_prob == 1.0);
    assert!((0.0..=1.0).contains(&params.unassigned_prob));

    // `leaves[i]` is the bit path of the i-th current leaf. The pop/swap dance
    // below mirrors asmap.py exactly so the shape distribution is the same.
    let mut leaves: Vec<Vec<bool>> = vec![Vec::new()];
    for i in 1..params.num_leaves as usize {
        let idx = rng.below(i as u64) as usize;
        let leaf = leaves[idx].clone();
        let lastleaf = leaves.pop().expect("leaves is never empty");
        if idx + 1 < i {
            leaves[idx] = lastleaf;
        }
        let mut left = leaf.clone();
        left.push(false);
        let mut right = leaf;
        right.push(true);
        leaves.push(left);
        leaves.push(right);
    }

    let entries: Vec<ASNEntry> = leaves
        .into_iter()
        .map(|prefix| {
            let asn = if rng.next_f64() >= params.unassigned_prob {
                rng.range(1, params.max_asn as u64 + 1) as u32
            } else {
                0
            };
            (prefix, asn)
        })
        .collect();

    let mut map = ASMap::new();
    map.update_multi(entries);
    map
}

/// Convenience wrapper: seed, draw parameters, build a map.
pub fn random_map_from_seed(seed: u64) -> (ASMap, RandomMapParams) {
    let mut rng = SplitMix64::new(seed);
    let params = RandomMapParams::draw(&mut rng);
    (random_map(&mut rng, params), params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_matches_reference_vectors() {
        // Reference stream for seed 0 from the canonical SplitMix64 listing.
        let mut rng = SplitMix64::new(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn generation_is_reproducible() {
        let (a, pa) = random_map_from_seed(1234);
        let (b, pb) = random_map_from_seed(1234);
        assert_eq!(pa, pb);
        assert_eq!(a, b);
    }

    #[test]
    fn below_stays_in_range() {
        let mut rng = SplitMix64::new(7);
        for _ in 0..1000 {
            assert!(rng.below(5) < 5);
            let f = rng.next_f64();
            assert!((0.0..1.0).contains(&f));
        }
    }
}
