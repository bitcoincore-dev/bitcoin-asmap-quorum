//! The in-memory ASMap prefix trie and its Bitcoin Core binary (de)serialization.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::coder::{
    BinNode, BinNodeKind, CODER_ASN, CODER_INS, CODER_JUMP, CODER_MATCH, Instruction,
};
use crate::net::{ASNDiff, ASNEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum TrieNode {
    Leaf(u32),
    Branch(Box<TrieNode>, Box<TrieNode>),
}

impl TrieNode {
    fn leaf(value: u32) -> Self {
        Self::Leaf(value)
    }

    fn branch(left: TrieNode, right: TrieNode) -> Self {
        match (left, right) {
            (TrieNode::Leaf(a), TrieNode::Leaf(b)) if a == b => TrieNode::Leaf(a),
            (l, r) => TrieNode::Branch(Box::new(l), Box::new(r)),
        }
    }
}

/// In-memory binary trie representation of an ASMap.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ASMap {
    trie: TrieNode,
}

impl Default for ASMap {
    fn default() -> Self {
        Self {
            trie: TrieNode::leaf(0),
        }
    }
}

impl ASMap {
    /// Creates an empty ASMap with all prefixes unassigned.
    pub fn new() -> Self {
        Self::default()
    }

    /// Assigns `asn` to a single prefix bit path.
    pub fn update(&mut self, prefix: &[bool], asn: u32) {
        fn recurse(node: &mut TrieNode, prefix: &[bool], asn: u32, offset: usize) {
            if offset == prefix.len() {
                *node = TrieNode::leaf(asn);
                return;
            }

            if let TrieNode::Leaf(value) = *node {
                *node = TrieNode::Branch(
                    Box::new(TrieNode::Leaf(value)),
                    Box::new(TrieNode::Leaf(value)),
                );
            }

            if let TrieNode::Branch(left, right) = node {
                recurse(
                    if prefix[offset] { right } else { left },
                    prefix,
                    asn,
                    offset + 1,
                );
            }

            if let TrieNode::Branch(left, right) = node
                && let (TrieNode::Leaf(a), TrieNode::Leaf(b)) = (&**left, &**right)
                && a == b
            {
                *node = TrieNode::leaf(*a);
            }
        }

        recurse(&mut self.trie, prefix, asn, 0);
    }

    /// Applies multiple prefix assignments in shortest-prefix-first order.
    pub fn update_multi(&mut self, mut entries: Vec<ASNEntry>) {
        entries.sort_by_key(|(prefix, _)| prefix.len());
        for (prefix, asn) in entries {
            self.update(&prefix, asn);
        }
    }

    /// Resolves a concrete prefix bit path to its ASN if one is assigned.
    pub fn lookup(&self, prefix: &[bool]) -> Option<u32> {
        let mut node = &self.trie;
        for bit in prefix {
            match node {
                TrieNode::Leaf(v) => return Some(*v),
                TrieNode::Branch(left, right) => node = if *bit { right } else { left },
            }
        }
        match node {
            TrieNode::Leaf(v) => Some(*v),
            TrieNode::Branch(_, _) => None,
        }
    }

    /// Returns true when `self` satisfies every non-zero assignment in `req`.
    pub fn extends(&self, req: &ASMap) -> bool {
        fn recurse(actual: &TrieNode, req: &TrieNode) -> bool {
            match req {
                TrieNode::Leaf(0) => true,
                TrieNode::Leaf(reqv) => match actual {
                    TrieNode::Leaf(av) => av == reqv,
                    TrieNode::Branch(left, right) => recurse(left, req) && recurse(right, req),
                },
                TrieNode::Branch(req_left, req_right) => match actual {
                    TrieNode::Leaf(_) => recurse(actual, req_left) && recurse(actual, req_right),
                    TrieNode::Branch(act_left, act_right) => {
                        recurse(act_left, req_left) && recurse(act_right, req_right)
                    }
                },
            }
        }

        recurse(&self.trie, &req.trie)
    }

    /// Computes prefix-level ASN changes between this map and `other`.
    pub fn diff(&self, other: &ASMap) -> Vec<ASNDiff> {
        fn recurse(prefix: &mut Vec<bool>, old: &TrieNode, new: &TrieNode, out: &mut Vec<ASNDiff>) {
            match (old, new) {
                (TrieNode::Leaf(a), TrieNode::Leaf(b)) => {
                    if a != b {
                        out.push((prefix.clone(), *a, *b));
                    }
                }
                _ => {
                    let old_left = match old {
                        TrieNode::Leaf(_) => old,
                        TrieNode::Branch(left, _) => left,
                    };
                    let old_right = match old {
                        TrieNode::Leaf(_) => old,
                        TrieNode::Branch(_, right) => right,
                    };
                    let new_left = match new {
                        TrieNode::Leaf(_) => new,
                        TrieNode::Branch(left, _) => left,
                    };
                    let new_right = match new {
                        TrieNode::Leaf(_) => new,
                        TrieNode::Branch(_, right) => right,
                    };
                    prefix.push(false);
                    recurse(prefix, old_left, new_left, out);
                    *prefix.last_mut().unwrap() = true;
                    recurse(prefix, old_right, new_right, out);
                    prefix.pop();
                }
            }
        }

        let mut out = Vec::new();
        recurse(&mut Vec::new(), &self.trie, &other.trie, &mut out);
        out
    }

    /// Converts the trie to a list of `(prefix, ASN)` assignments.
    ///
    /// `AS0` (unassigned) is never emitted, with or without `fill`.
    ///
    /// `fill` permits the emitted entries to cover subnets that are *unassigned*
    /// in this map, which can shorten the list. It is lossy: the result no longer
    /// round-trips to an equal map, only to one that [`ASMap::extends`] this one.
    ///
    /// `overlapping` permits the emitted subnets to overlap, which can shorten
    /// the list considerably. Overlapping output is only meaningful to a consumer
    /// that applies entries shortest-prefix-first, as [`ASMap::update_multi`]
    /// does — longer prefixes override the ranges they sit inside.
    ///
    /// Mirrors `ASMap.to_entries` in `contrib/asmap/asmap.py`. Note the argument
    /// order is `(fill, overlapping)` here and `(overlapping, fill)` there.
    pub fn to_entries(&self, fill: bool, overlapping: bool) -> Vec<ASNEntry> {
        if overlapping {
            self.to_entries_minimal(fill)
        } else {
            self.to_entries_flat(fill)
        }
    }

    /// Non-overlapping entry list — a port of `ASMap._to_entries_flat`.
    fn to_entries_flat(&self, fill: bool) -> Vec<ASNEntry> {
        fn recurse(node: &TrieNode, prefix: &mut Vec<bool>, fill: bool) -> Vec<ASNEntry> {
            match node {
                TrieNode::Leaf(v) => {
                    if *v > 0 {
                        vec![(prefix.clone(), *v)]
                    } else {
                        Vec::new()
                    }
                }
                TrieNode::Branch(left, right) => {
                    prefix.push(false);
                    let mut ret = recurse(left, prefix, fill);
                    *prefix.last_mut().unwrap() = true;
                    ret.extend(recurse(right, prefix, fill));
                    prefix.pop();
                    // With `fill`, a subtree whose every entry carries the same
                    // ASN collapses to one entry for this node's own prefix. Any
                    // unassigned space inside contributed no entries, so it is
                    // absorbed — that is exactly what `fill` licenses. A subtree
                    // yielding a single deep entry is deliberately not widened.
                    if fill && ret.len() > 1 {
                        let first = ret[0].1;
                        if ret.iter().all(|(_, asn)| *asn == first) {
                            ret = vec![(prefix.clone(), first)];
                        }
                    }
                    ret
                }
            }
        }

        recurse(&self.trie, &mut Vec::new(), fill)
    }

    /// Minimal overlapping entry list — a port of `ASMap._to_entries_minimal`.
    ///
    /// The recursion returns, for each *context*, the entries needed to describe
    /// the subtree. A context of `Some(k)` means "given an enclosing entry that
    /// already maps this whole range to ASN `k`"; `None` means "standalone, with
    /// no enclosing entry". The boolean is `hole`: the subtree contains
    /// unassigned space that a covering entry must not claim.
    fn to_entries_minimal(&self, fill: bool) -> Vec<ASNEntry> {
        type Ctx = Option<u32>;
        type CtxMap = BTreeMap<Ctx, Vec<ASNEntry>>;

        /// Records `a ++ b` for `ctx` when both halves exist and the result is
        /// *strictly* shorter than what is already there (so the first insertion
        /// wins ties, as in the Python).
        fn candidate(
            ret: &mut CtxMap,
            ctx: Ctx,
            a: Option<&Vec<ASNEntry>>,
            b: Option<&Vec<ASNEntry>>,
        ) {
            let (Some(a), Some(b)) = (a, b) else { return };
            let replace = ret
                .get(&ctx)
                .map(|old| a.len() + b.len() < old.len())
                .unwrap_or(true);
            if replace {
                let mut combined = Vec::with_capacity(a.len() + b.len());
                combined.extend_from_slice(a);
                combined.extend_from_slice(b);
                ret.insert(ctx, combined);
            }
        }

        fn recurse(node: &TrieNode, prefix: &mut Vec<bool>, fill: bool) -> (CtxMap, bool) {
            match node {
                TrieNode::Leaf(0) => {
                    let mut ret = CtxMap::new();
                    ret.insert(if fill { None } else { Some(0) }, Vec::new());
                    (ret, true)
                }
                TrieNode::Leaf(v) => {
                    let mut ret = CtxMap::new();
                    ret.insert(Some(*v), Vec::new());
                    ret.insert(None, vec![(prefix.clone(), *v)]);
                    (ret, false)
                }
                TrieNode::Branch(left, right) => {
                    prefix.push(false);
                    let (left_map, lhole) = recurse(left, prefix, fill);
                    *prefix.last_mut().unwrap() = true;
                    let (right_map, rhole) = recurse(right, prefix, fill);
                    prefix.pop();

                    let hole = !fill && (lhole || rhole);
                    let mut ret = CtxMap::new();

                    // Python iterates `set(left) | set(right)`, whose order is
                    // unspecified. Fix it to `Some(n)` ascending then `None` last
                    // — the `(x is None, x)` convention used elsewhere in the
                    // Python — so ties resolve deterministically.
                    let union: BTreeSet<Ctx> =
                        left_map.keys().chain(right_map.keys()).copied().collect();
                    let mut order: Vec<Ctx> =
                        union.iter().copied().filter(Option::is_some).collect();
                    if union.contains(&None) {
                        order.push(None);
                    }

                    for ctx in order {
                        candidate(&mut ret, ctx, left_map.get(&ctx), right_map.get(&ctx));
                        candidate(&mut ret, ctx, left_map.get(&None), right_map.get(&ctx));
                        candidate(&mut ret, ctx, left_map.get(&ctx), right_map.get(&None));
                    }

                    // Offer "one entry covering this whole node, plus the
                    // ctx-relative fix-ups". Forbidden when the subtree has a
                    // hole, since the covering entry would claim unassigned space.
                    if !hole {
                        let snapshot: Vec<u32> = ret.keys().filter_map(|ctx| *ctx).collect();
                        for asn in snapshot {
                            // The loop only ever writes key `None`, so reading
                            // `ret[Some(asn)]` here matches Python's snapshot.
                            let fixups = ret[&Some(asn)].clone();
                            let cover = vec![(prefix.clone(), asn)];
                            candidate(&mut ret, None, Some(&cover), Some(&fixups));
                        }
                    }

                    if let Some(best) = ret.get(&None).map(Vec::len) {
                        ret.retain(|ctx, entries| ctx.is_none() || entries.len() < best);
                    }
                    if hole {
                        ret.retain(|ctx, _| ctx.is_none() || *ctx == Some(0));
                    }
                    (ret, hole)
                }
            }
        }

        // The ambient context at the top level is 0 (unassigned). Python would
        // raise KeyError if neither key is present; that is unreachable, and an
        // empty list is the safe equivalent.
        let (mut res, _) = recurse(&self.trie, &mut Vec::new(), fill);
        match res.remove(&Some(0)) {
            Some(entries) => entries,
            None => res.remove(&None).unwrap_or_default(),
        }
    }

    pub(crate) fn to_binnode(&self, fill: bool) -> BinNode {
        fn recurse(node: &TrieNode, fill: bool) -> (HashMap<Option<u32>, BinNode>, bool) {
            match node {
                TrieNode::Leaf(0) => {
                    let mut ret = HashMap::new();
                    ret.insert(if fill { None } else { Some(0) }, BinNode::end());
                    (ret, true)
                }
                TrieNode::Leaf(v) => {
                    let mut ret = HashMap::new();
                    ret.insert(None, BinNode::leaf(*v));
                    ret.insert(Some(*v), BinNode::end());
                    (ret, false)
                }
                TrieNode::Branch(left, right) => {
                    let (left_map, left_hole) = recurse(left, fill);
                    let (right_map, right_hole) = recurse(right, fill);
                    let hole = (left_hole || right_hole) && !fill;
                    let mut ret: HashMap<Option<u32>, BinNode> = HashMap::new();
                    let mut union = BTreeSet::new();
                    for k in left_map.keys().chain(right_map.keys()) {
                        union.insert(*k);
                    }

                    let mut candidate =
                        |ctx: Option<u32>,
                         a: Option<&BinNode>,
                         b: Option<&BinNode>,
                         f: fn(BinNode, BinNode) -> BinNode| {
                            if let (Some(a), Some(b)) = (a, b) {
                                let cand = f(a.clone(), b.clone());
                                let replace = ret
                                    .get(&ctx)
                                    .map(|old| cand.size < old.size)
                                    .unwrap_or(true);
                                if replace {
                                    ret.insert(ctx, cand);
                                }
                            }
                        };

                    for ctx in union {
                        candidate(
                            ctx,
                            left_map.get(&ctx),
                            right_map.get(&ctx),
                            BinNode::branch,
                        );
                        candidate(
                            ctx,
                            left_map.get(&None),
                            right_map.get(&ctx),
                            BinNode::branch,
                        );
                        candidate(
                            ctx,
                            left_map.get(&ctx),
                            right_map.get(&None),
                            BinNode::branch,
                        );
                    }

                    if !hole {
                        let mut keys: Vec<Option<u32>> =
                            ret.keys().copied().filter(|k| k.is_some()).collect();
                        keys.sort();
                        for ctx in keys {
                            let node = ret.get(&ctx).cloned().unwrap();
                            let defaulted = BinNode::default(ctx.unwrap(), node);
                            let replace = ret
                                .get(&None)
                                .map(|old| defaulted.size < old.size)
                                .unwrap_or(true);
                            if replace {
                                ret.insert(None, defaulted);
                            }
                        }
                    }

                    if let Some(best_default) = ret.get(&None).map(|node| node.size) {
                        ret.retain(|ctx, enc| ctx.is_none() || enc.size < best_default);
                    }
                    if hole {
                        ret.retain(|ctx, _| ctx.is_none() || *ctx == Some(0));
                    }
                    (ret, hole)
                }
            }
        }

        let (res, _) = recurse(&self.trie, fill);
        res.get(&Some(0))
            .cloned()
            .or_else(|| res.get(&None).cloned())
            .unwrap_or_else(BinNode::end)
    }

    /// Serializes the ASMap to Bitcoin Core compatible binary format.
    pub fn to_binary(&self, fill: bool) -> Vec<u8> {
        fn encode(node: &BinNode, bits: &mut Vec<u8>) {
            CODER_INS.encode(node.ins_value(), bits);
            match &node.kind {
                BinNodeKind::Return(v) => CODER_ASN.encode(*v, bits),
                BinNodeKind::Jump(left, right) => {
                    CODER_JUMP.encode(left.size as u32, bits);
                    encode(left, bits);
                    encode(right, bits);
                }
                BinNodeKind::Match(v, sub) => {
                    CODER_MATCH.encode(*v, bits);
                    encode(sub, bits);
                }
                BinNodeKind::Default(v, sub) => {
                    CODER_ASN.encode(*v, bits);
                    encode(sub, bits);
                }
                BinNodeKind::End => {}
            }
        }

        let binnode = self.to_binnode(fill);
        let mut bits = Vec::new();
        if !matches!(binnode.kind, BinNodeKind::End) {
            encode(&binnode, &mut bits);
        }
        let mut bytes = Vec::new();
        let mut val = 0u8;
        let mut nbits = 0u8;
        for bit in bits {
            val |= bit << nbits;
            nbits += 1;
            if nbits == 8 {
                bytes.push(val);
                val = 0;
                nbits = 0;
            }
        }
        if nbits != 0 {
            bytes.push(val);
        }
        bytes
    }

    /// Deserializes a Bitcoin Core ASMap binary payload.
    pub fn from_binary(bindata: &[u8]) -> Option<Self> {
        let mut bits = Vec::with_capacity(bindata.len() * 8);
        for byte in bindata {
            for i in 0..8 {
                bits.push((byte >> i) & 1);
            }
        }

        fn recurse(bits: &[u8], bitpos: usize) -> Option<(BinNode, usize)> {
            let (insval, bitpos) = CODER_INS.decode(bits, bitpos)?;
            let ins = Instruction::try_from(insval).ok()?;
            match ins {
                Instruction::Return => {
                    let (asn, bitpos) = CODER_ASN.decode(bits, bitpos)?;
                    Some((BinNode::leaf(asn), bitpos))
                }
                Instruction::Jump => {
                    let (jump, bitpos) = CODER_JUMP.decode(bits, bitpos)?;
                    let (left, bitpos1) = recurse(bits, bitpos)?;
                    if bitpos1 != bitpos + jump as usize {
                        return None;
                    }
                    let (right, bitpos2) = recurse(bits, bitpos1)?;
                    Some((BinNode::branch(left, right), bitpos2))
                }
                Instruction::Match => {
                    let (matchval, bitpos) = CODER_MATCH.decode(bits, bitpos)?;
                    let (sub, bitpos) = recurse(bits, bitpos)?;
                    Some((BinNode::match_node(matchval, sub), bitpos))
                }
                Instruction::Default => {
                    let (asn, bitpos) = CODER_ASN.decode(bits, bitpos)?;
                    let (sub, bitpos) = recurse(bits, bitpos)?;
                    Some((BinNode::default(asn, sub), bitpos))
                }
                Instruction::End => Some((BinNode::end(), bitpos)),
            }
        }

        if bits.is_empty() {
            return Some(Self::new());
        }
        let (binnode, bitpos) = recurse(&bits, 0)?;
        if bitpos < bits.len().saturating_sub(7) {
            return None;
        }
        if bits[bitpos..].iter().any(|b| *b != 0) {
            return None;
        }
        Self::from_binnode(binnode)
    }

    fn from_binnode(node: BinNode) -> Option<Self> {
        fn recurse(node: BinNode, default: u32) -> Option<TrieNode> {
            match node.kind {
                BinNodeKind::Return(v) => Some(TrieNode::leaf(v)),
                BinNodeKind::Jump(left, right) => Some(TrieNode::branch(
                    recurse(*left, default)?,
                    recurse(*right, default)?,
                )),
                BinNodeKind::Match(mut val, sub) => {
                    let mut sub = recurse(*sub, default)?;
                    while val >= 2 {
                        let bit = val & 1;
                        val >>= 1;
                        sub = if bit != 0 {
                            TrieNode::branch(TrieNode::leaf(default), sub)
                        } else {
                            TrieNode::branch(sub, TrieNode::leaf(default))
                        };
                    }
                    Some(sub)
                }
                BinNodeKind::Default(v, sub) => recurse(*sub, v),
                BinNodeKind::End => None,
            }
        }

        let trie = match node.kind {
            BinNodeKind::End => TrieNode::leaf(0),
            _ => recurse(node, 0)?,
        };
        Some(Self { trie })
    }
}
