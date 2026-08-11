use anyhow::{Context, Result, anyhow, bail};
use futures::StreamExt;
use libp2p::{
    PeerId, SwarmBuilder, gossipsub, mdns,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use log::{debug, info, trace, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;
use tokio::time::interval;

type ASNEntry = (Vec<bool>, u32);
type ASNDiff = (Vec<bool>, u32, u32);

fn bit_length_u32(v: u32) -> u32 {
    32 - v.leading_zeros()
}

fn parse_network_prefix(input: &str) -> Result<(IpAddr, u8)> {
    let (addr, prefix) = input
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid network '{input}'"))?;
    let ip: IpAddr = addr
        .parse()
        .with_context(|| format!("invalid network '{input}'"))?;
    let prefix_len: u8 = prefix
        .parse()
        .with_context(|| format!("invalid network '{input}'"))?;
    match ip {
        IpAddr::V4(_) if prefix_len <= 32 => Ok((ip, prefix_len)),
        IpAddr::V6(_) if prefix_len <= 128 => Ok((ip, prefix_len)),
        _ => bail!("invalid network '{input}'"),
    }
}

fn ip_to_bits(ip: IpAddr, prefix_len: u8) -> Vec<bool> {
    let (netrange, num_bits) = match ip {
        IpAddr::V4(v4) => (
            (u32::from(v4) as u128) + 0xffff_0000_0000u128,
            prefix_len as usize + 96,
        ),
        IpAddr::V6(v6) => (u128::from_be_bytes(v6.octets()), prefix_len as usize),
    };
    (0..num_bits)
        .map(|i| ((netrange >> (127 - i)) & 1) != 0)
        .collect()
}

fn bits_to_network(prefix: &[bool]) -> String {
    let netrange = prefix.iter().enumerate().fold(0u128, |acc, (i, bit)| {
        if *bit {
            acc | (1u128 << (127 - i))
        } else {
            acc
        }
    });
    if prefix.len() >= 96 && (netrange >> 32) == 0xffff {
        let addr = Ipv4Addr::from((netrange & 0xffff_ffff) as u32);
        format!("{addr}/{}", prefix.len() - 96)
    } else {
        format!("{}/{}", Ipv6Addr::from(netrange), prefix.len())
    }
}

fn network_address_count(net: &str) -> Result<u128> {
    let (_, prefix_len) = net
        .rsplit_once('/')
        .ok_or_else(|| anyhow!("invalid network '{net}'"))?;
    let prefix_len: u32 = prefix_len.parse()?;
    if net.contains('.') {
        Ok(1u128 << (32 - prefix_len))
    } else {
        Ok(1u128.checked_shl(128 - prefix_len).unwrap_or(u128::MAX))
    }
}

fn canonical_claim_bytes(epoch: u64, sender_id: &str, entries: &[AsmapEntry]) -> Vec<u8> {
    let mut entries = entries.to_vec();
    entries.sort_by(|a, b| {
        a.ip_prefix
            .cmp(&b.ip_prefix)
            .then_with(|| a.asn.cmp(&b.asn))
    });

    let mut bytes = Vec::new();
    bytes.extend_from_slice(format!("epoch={epoch}\nsender={sender_id}\n").as_bytes());
    for entry in entries {
        bytes.extend_from_slice(format!("{}|{}\n", entry.ip_prefix, entry.asn).as_bytes());
    }
    bytes
}

fn claim_hash(epoch: u64, sender_id: &str, entries: &[AsmapEntry]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_claim_bytes(epoch, sender_id, entries));
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum TrieNode {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn new() -> Self {
        Self::default()
    }

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

    pub fn update_multi(&mut self, mut entries: Vec<ASNEntry>) {
        entries.sort_by_key(|(prefix, _)| prefix.len());
        for (prefix, asn) in entries {
            self.update(&prefix, asn);
        }
    }

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

    pub fn to_entries(&self, fill: bool, _overlapping: bool) -> Vec<ASNEntry> {
        fn recurse(node: &TrieNode, prefix: &mut Vec<bool>, fill: bool, out: &mut Vec<ASNEntry>) {
            match node {
                TrieNode::Leaf(v) => {
                    if *v > 0 {
                        out.push((prefix.clone(), *v));
                    }
                }
                TrieNode::Branch(left, right) => {
                    if fill
                        && let (TrieNode::Leaf(a), TrieNode::Leaf(b)) = (&**left, &**right)
                        && a == b
                        && *a > 0
                    {
                        out.push((prefix.clone(), *a));
                        return;
                    }
                    prefix.push(false);
                    recurse(left, prefix, fill, out);
                    *prefix.last_mut().unwrap() = true;
                    recurse(right, prefix, fill, out);
                    prefix.pop();
                }
            }
        }

        let mut out = Vec::new();
        recurse(&self.trie, &mut Vec::new(), fill, &mut out);
        out
    }

    fn to_binnode(&self, fill: bool) -> BinNode {
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
                        let keys: Vec<Option<u32>> =
                            ret.keys().copied().filter(|k| k.is_some()).collect();
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

    pub fn to_binary(&self, fill: bool) -> Vec<u8> {
        fn encode(node: &BinNode, bits: &mut Vec<u8>) {
            _CODER_INS.encode(node.ins_value(), bits);
            match &node.kind {
                BinNodeKind::Return(v) => _CODER_ASN.encode(*v, bits),
                BinNodeKind::Jump(left, right) => {
                    _CODER_JUMP.encode(left.size as u32, bits);
                    encode(left, bits);
                    encode(right, bits);
                }
                BinNodeKind::Match(v, sub) => {
                    _CODER_MATCH.encode(*v, bits);
                    encode(sub, bits);
                }
                BinNodeKind::Default(v, sub) => {
                    _CODER_ASN.encode(*v, bits);
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

    pub fn from_binary(bindata: &[u8]) -> Option<Self> {
        let mut bits = Vec::with_capacity(bindata.len() * 8);
        for byte in bindata {
            for i in 0..8 {
                bits.push((byte >> i) & 1);
            }
        }

        fn recurse(bits: &[u8], bitpos: usize) -> Option<(BinNode, usize)> {
            let (insval, bitpos) = _CODER_INS.decode(bits, bitpos)?;
            let ins = Instruction::try_from(insval).ok()?;
            match ins {
                Instruction::Return => {
                    let (asn, bitpos) = _CODER_ASN.decode(bits, bitpos)?;
                    Some((BinNode::leaf(asn), bitpos))
                }
                Instruction::Jump => {
                    let (jump, bitpos) = _CODER_JUMP.decode(bits, bitpos)?;
                    let (left, bitpos1) = recurse(bits, bitpos)?;
                    if bitpos1 != bitpos + jump as usize {
                        return None;
                    }
                    let (right, bitpos2) = recurse(bits, bitpos1)?;
                    Some((BinNode::branch(left, right), bitpos2))
                }
                Instruction::Match => {
                    let (matchval, bitpos) = _CODER_MATCH.decode(bits, bitpos)?;
                    let (sub, bitpos) = recurse(bits, bitpos)?;
                    Some((BinNode::match_node(matchval, sub), bitpos))
                }
                Instruction::Default => {
                    let (asn, bitpos) = _CODER_ASN.decode(bits, bitpos)?;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Instruction {
    Return = 0,
    Jump = 1,
    Match = 2,
    Default = 3,
    End = 4,
}

impl TryFrom<u32> for Instruction {
    type Error = ();

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            0 => Instruction::Return,
            1 => Instruction::Jump,
            2 => Instruction::Match,
            3 => Instruction::Default,
            4 => Instruction::End,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone)]
struct VarLenCoder {
    minval: u32,
    clsbits: &'static [u32],
    maxval: u32,
}

impl VarLenCoder {
    const fn new(minval: u32, clsbits: &'static [u32]) -> Self {
        let mut total = 0u32;
        let mut i = 0;
        while i < clsbits.len() {
            total += 1 << clsbits[i];
            i += 1;
        }
        Self {
            minval,
            clsbits,
            maxval: minval + total - 1,
        }
    }

    fn can_encode(&self, val: u32) -> bool {
        (self.minval..=self.maxval).contains(&val)
    }

    fn encode_size(&self, val: u32) -> usize {
        let mut val = val - self.minval;
        let mut ret = 0usize;
        let mut bits = 0u32;
        for (k, clsbits) in self.clsbits.iter().enumerate() {
            bits = *clsbits;
            if val >> bits != 0 {
                val -= 1 << bits;
                ret += 1;
            } else {
                ret += usize::from(k + 1 < self.clsbits.len());
                break;
            }
        }
        ret + bits as usize
    }

    fn encode(&self, val: u32, ret: &mut Vec<u8>) {
        assert!(self.can_encode(val));
        let mut val = val - self.minval;
        let mut bits = 0u32;
        for (k, clsbits) in self.clsbits.iter().enumerate() {
            bits = *clsbits;
            if val >> bits != 0 {
                val -= 1 << bits;
                ret.push(1);
            } else {
                if k + 1 < self.clsbits.len() {
                    ret.push(0);
                }
                break;
            }
        }
        for b in 0..bits {
            ret.push(((val >> (bits - 1 - b)) & 1) as u8);
        }
    }

    fn decode(&self, stream: &[u8], mut bitpos: usize) -> Option<(u32, usize)> {
        let mut val = self.minval;
        let mut bits = 0u32;
        for (k, clsbits) in self.clsbits.iter().enumerate() {
            bits = *clsbits;
            let mut bit = 0u8;
            if k + 1 < self.clsbits.len() {
                bit = *stream.get(bitpos)?;
                bitpos += 1;
            }
            if bit == 0 {
                break;
            }
            val += 1 << bits;
        }
        for i in 0..bits {
            let bit = *stream.get(bitpos)?;
            bitpos += 1;
            val += (bit as u32) << (bits - 1 - i);
        }
        Some((val, bitpos))
    }
}

#[derive(Debug, Clone)]
enum BinNodeKind {
    Return(u32),
    Jump(Box<BinNode>, Box<BinNode>),
    Match(u32, Box<BinNode>),
    Default(u32, Box<BinNode>),
    End,
}

#[derive(Debug, Clone)]
struct BinNode {
    kind: BinNodeKind,
    size: usize,
}

impl BinNode {
    fn end() -> Self {
        Self {
            kind: BinNodeKind::End,
            size: 0,
        }
    }

    fn leaf(v: u32) -> Self {
        Self {
            kind: BinNodeKind::Return(v),
            size: _CODER_INS.encode_size(Instruction::Return as u32) + _CODER_ASN.encode_size(v),
        }
    }

    fn branch(left: BinNode, right: BinNode) -> Self {
        if matches!(left.kind, BinNodeKind::End) && matches!(right.kind, BinNodeKind::End) {
            return left;
        }
        if matches!(left.kind, BinNodeKind::End) {
            if let BinNodeKind::Match(v, sub) = right.kind.clone()
                && v <= 0xff
            {
                return Self::match_node(v + (1 << bit_length_u32(v)), *sub);
            }
            return Self::match_node(3, right);
        }
        if matches!(right.kind, BinNodeKind::End) {
            if let BinNodeKind::Match(v, sub) = left.kind.clone()
                && v <= 0xff
            {
                return Self::match_node(v + (1 << (bit_length_u32(v) - 1)), *sub);
            }
            return Self::match_node(2, left);
        }
        let size = _CODER_INS.encode_size(Instruction::Jump as u32)
            + _CODER_JUMP.encode_size(left.size as u32)
            + left.size
            + right.size;
        Self {
            kind: BinNodeKind::Jump(Box::new(left), Box::new(right)),
            size,
        }
    }

    fn default(v: u32, sub: BinNode) -> Self {
        if matches!(sub.kind, BinNodeKind::End) {
            return Self::leaf(v);
        }
        if matches!(
            sub.kind,
            BinNodeKind::Return(_) | BinNodeKind::Default(_, _)
        ) {
            return sub;
        }
        let size = _CODER_INS.encode_size(Instruction::Default as u32)
            + _CODER_ASN.encode_size(v)
            + sub.size;
        Self {
            kind: BinNodeKind::Default(v, Box::new(sub)),
            size,
        }
    }

    fn match_node(v: u32, sub: BinNode) -> Self {
        let size = _CODER_INS.encode_size(Instruction::Match as u32)
            + _CODER_MATCH.encode_size(v)
            + sub.size;
        Self {
            kind: BinNodeKind::Match(v, Box::new(sub)),
            size,
        }
    }

    fn ins_value(&self) -> u32 {
        match self.kind {
            BinNodeKind::Return(_) => Instruction::Return as u32,
            BinNodeKind::Jump(_, _) => Instruction::Jump as u32,
            BinNodeKind::Match(_, _) => Instruction::Match as u32,
            BinNodeKind::Default(_, _) => Instruction::Default as u32,
            BinNodeKind::End => Instruction::End as u32,
        }
    }
}

const _CODER_INS: VarLenCoder = VarLenCoder::new(0, &[0, 0, 1]);
const _CODER_ASN: VarLenCoder = VarLenCoder::new(1, &[15, 16, 17, 18, 19, 20, 21, 22, 23, 24]);
const _CODER_MATCH: VarLenCoder = VarLenCoder::new(2, &[1, 2, 3, 4, 5, 6, 7, 8]);
const _CODER_JUMP: VarLenCoder = VarLenCoder::new(
    17,
    &[
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
        29, 30,
    ],
);

#[derive(Deserialize)]
struct AddrInfo {
    address: String,
    network: String,
}

fn open_input(path: Option<&str>) -> Result<Box<dyn Read>> {
    match path {
        Some("-") | None => Ok(Box::new(io::stdin())),
        Some(path) => {
            Ok(Box::new(File::open(path).with_context(|| {
                format!("Input file '{path}' cannot be read")
            })?))
        }
    }
}

fn open_output(path: Option<&str>, binary: bool) -> Result<Box<dyn Write>> {
    match path {
        Some("-") | None => {
            if binary && io::stdout().is_terminal() {
                bail!(
                    "Not much use in writing binary to a TTY. Please specify an output file or pipe output to another process."
                );
            }
            Ok(Box::new(io::stdout()))
        }
        Some(path) => {
            Ok(Box::new(File::create(path).with_context(|| {
                format!("Output file '{path}' cannot be written to")
            })?))
        }
    }
}

fn load_file(mut input: Box<dyn Read>, input_name: &str) -> Result<ASMap> {
    let mut contents = Vec::new();
    input
        .read_to_end(&mut contents)
        .with_context(|| format!("Input file '{input_name}' cannot be read"))?;

    let bin_asmap = ASMap::from_binary(&contents);
    let mut txt_error = None;
    let mut entries: Option<Vec<ASNEntry>> = None;

    if let Ok(txt_contents) = std::str::from_utf8(&contents) {
        let mut parsed = Vec::new();
        for line in txt_contents.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let prefix = fields.next();
            let asn = fields.next();
            if prefix.is_none() || asn.is_none() || fields.next().is_some() {
                txt_error = Some(format!("unparseable line '{line}'"));
                parsed.clear();
                break;
            }
            let asn = asn.unwrap();
            if !asn.starts_with("AS")
                || asn.len() <= 2
                || !asn[2..].chars().all(|c| c.is_ascii_digit())
            {
                txt_error = Some(format!("invalid ASN '{asn}'"));
                parsed.clear();
                break;
            }
            let net = parse_network_prefix(prefix.unwrap())?;
            parsed.push((ip_to_bits(net.0, net.1), asn[2..].parse()?));
        }
        entries = Some(parsed);
    } else {
        txt_error = Some("invalid UTF-8".to_string());
    }

    if entries.is_some() && bin_asmap.is_some() && !contents.is_empty() {
        bail!("Input file '{input_name}' is ambiguous.");
    }
    if let Some(entries) = entries {
        let mut state = ASMap::new();
        state.update_multi(entries);
        return Ok(state);
    }
    if let Some(state) = bin_asmap {
        return Ok(state);
    }
    bail!(
        "Input file '{input_name}' is neither a valid binary asmap file nor valid text input ({})",
        txt_error.unwrap_or_else(|| "unparseable".to_string())
    )
}

fn save_binary(
    mut output: Box<dyn Write>,
    state: &ASMap,
    fill: bool,
    output_name: &str,
) -> Result<()> {
    let contents = state.to_binary(fill);
    output
        .write_all(&contents)
        .with_context(|| format!("Output file '{output_name}' cannot be written to"))?;
    Ok(())
}

fn save_json_report(path: &Path, artifact: &ConsensusArtifact) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Output file '{}' cannot be written to", path.display()))?;
    serde_json::to_writer_pretty(file, artifact)?;
    Ok(())
}

fn load_json_report(path: &str) -> Result<ConsensusArtifact> {
    let file = File::open(path).with_context(|| format!("Input file '{path}' cannot be read"))?;
    Ok(serde_json::from_reader(file)?)
}

fn load_claims(path: &str) -> Result<Vec<AsmapClaim>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Input file '{path}' cannot be read"))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(claims) = serde_json::from_str::<Vec<AsmapClaim>>(&raw) {
        return Ok(claims);
    }

    let mut claims = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let claim: AsmapClaim = serde_json::from_str(line)
            .with_context(|| format!("invalid claim on line {}", idx + 1))?;
        claims.push(claim);
    }
    Ok(claims)
}

fn verify_report(report_path: &str, map_path: Option<&str>) -> Result<()> {
    let artifact = load_json_report(report_path)?;
    let expected_entries: Vec<(Vec<bool>, u32)> = artifact
        .entries
        .iter()
        .map(|entry| {
            let (ip, prefix_len) = parse_network_prefix(&entry.ip_prefix)?;
            Ok((ip_to_bits(ip, prefix_len), entry.asn))
        })
        .collect::<Result<_>>()?;

    let mut expected = ASMap::new();
    expected.update_multi(expected_entries);

    if expected != artifact.map {
        bail!("report map does not match the published consensus entries");
    }

    if let Some(map_path) = map_path {
        let map = load_file(open_input(Some(map_path))?, map_path)?;
        if map != artifact.map {
            bail!("binary/text map does not match the report artifact");
        }
    }

    Ok(())
}

fn save_text(
    mut output: Box<dyn Write>,
    state: &ASMap,
    fill: bool,
    overlapping: bool,
    output_name: &str,
) -> Result<()> {
    for (prefix, asn) in state.to_entries(fill, overlapping) {
        let net = bits_to_network(&prefix);
        writeln!(output, "{net} AS{asn}")
            .with_context(|| format!("Output file '{output_name}' cannot be written to"))?;
    }
    Ok(())
}

fn run_encode(args: &[String]) -> Result<()> {
    let mut fill = false;
    let mut pos = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-f" | "--fill" => fill = true,
            _ => pos.push(arg.clone()),
        }
    }
    let infile = pos.first().map(String::as_str);
    let outfile = pos.get(1).map(String::as_str);
    let input_name = infile.unwrap_or("<stdin>");
    let output_name = outfile.unwrap_or("<stdout>");
    let state = load_file(open_input(infile)?, input_name)?;
    save_binary(open_output(outfile, true)?, &state, fill, output_name)
}

fn run_decode(args: &[String]) -> Result<()> {
    let mut fill = false;
    let mut overlapping = true;
    let mut pos = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-f" | "--fill" => fill = true,
            "-n" | "--nonoverlapping" => overlapping = false,
            _ => pos.push(arg.clone()),
        }
    }
    let infile = pos.first().map(String::as_str);
    let outfile = pos.get(1).map(String::as_str);
    let input_name = infile.unwrap_or("<stdin>");
    let output_name = outfile.unwrap_or("<stdout>");
    let state = load_file(open_input(infile)?, input_name)?;
    save_text(
        open_output(outfile, false)?,
        &state,
        fill,
        overlapping,
        output_name,
    )
}

fn run_diff(args: &[String]) -> Result<()> {
    let mut ignore_unassigned = false;
    let mut pos = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-i" | "--ignore-unassigned" => ignore_unassigned = true,
            _ => pos.push(arg.clone()),
        }
    }
    if pos.len() != 2 {
        bail!("diff requires two input files");
    }
    let state1 = load_file(open_input(Some(&pos[0]))?, &pos[0])?;
    let state2 = load_file(open_input(Some(&pos[1]))?, &pos[1])?;
    let mut ipv4_changed = 0u128;
    let mut ipv4_entries_changed = 0usize;
    let mut ipv6_changed = 0u128;
    let mut ipv6_entries_changed = 0usize;

    for (prefix, old_asn, new_asn) in state1.diff(&state2) {
        if ignore_unassigned && old_asn == 0 {
            continue;
        }
        let net = bits_to_network(&prefix);
        let count = network_address_count(&net)?;
        if net.contains('.') {
            ipv4_changed += count;
            ipv4_entries_changed += 1;
        } else {
            ipv6_changed += count;
            ipv6_entries_changed += 1;
        }
        if new_asn == 0 {
            println!("# {net} was AS{old_asn}");
        } else if old_asn == 0 {
            println!("{net} AS{new_asn} # was unassigned");
        } else {
            println!("{net} AS{new_asn} # was AS{old_asn}");
        }
    }
    let ipv4_change_str = if ipv4_changed == 0 {
        String::new()
    } else {
        format!(" (2^{:.2})", (ipv4_changed as f64).log2())
    };
    let ipv6_change_str = if ipv6_changed == 0 {
        String::new()
    } else {
        format!(" (2^{:.2})", (ipv6_changed as f64).log2())
    };
    println!(
        "# Summary\nIPv4: {ipv4_entries_changed} entries with {ipv4_changed}{ipv4_change_str} addresses changed\nIPv6: {ipv6_entries_changed} entries with {ipv6_changed}{ipv6_change_str} addresses changed"
    );
    Ok(())
}

fn run_diff_addrs(args: &[String]) -> Result<()> {
    let mut show_addresses = false;
    let mut pos = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-s" | "--show-addresses" => show_addresses = true,
            _ => pos.push(arg.clone()),
        }
    }
    if pos.len() != 3 {
        bail!("diff_addrs requires two input files and an address file");
    }
    let state1 = load_file(open_input(Some(&pos[0]))?, &pos[0])?;
    let state2 = load_file(open_input(Some(&pos[1]))?, &pos[1])?;
    let addrs_file =
        File::open(&pos[2]).with_context(|| format!("Input file '{}' cannot be read", pos[2]))?;
    let address_info: Vec<AddrInfo> = serde_json::from_reader(addrs_file)?;
    let addrs: Vec<String> = address_info
        .into_iter()
        .filter(|a| a.network == "ipv4" || a.network == "ipv6")
        .map(|a| a.address)
        .collect();

    let mut reassignments: HashMap<(u32, u32), Vec<String>> = HashMap::new();
    for addr in &addrs {
        let ip: IpAddr = addr
            .parse()
            .with_context(|| format!("invalid address '{addr}'"))?;
        let prefix = match ip {
            IpAddr::V4(v4) => ip_to_bits(IpAddr::V4(v4), 32),
            IpAddr::V6(v6) => ip_to_bits(IpAddr::V6(v6), 128),
        };
        let old_asn = state1.lookup(&prefix).unwrap_or(0);
        let new_asn = state2.lookup(&prefix).unwrap_or(0);
        if new_asn != old_asn {
            reassignments
                .entry((old_asn, new_asn))
                .or_default()
                .push(addr.clone());
        }
    }

    let mut reassignments: Vec<_> = reassignments.into_iter().collect();
    reassignments.sort_by_key(|a| std::cmp::Reverse(a.1.len()));
    let mut num_reassignment_type = HashMap::<(bool, bool), usize>::new();
    for ((old_asn, new_asn), reassigned_addrs) in &reassignments {
        let num_reassigned = reassigned_addrs.len();
        *num_reassignment_type
            .entry(((*old_asn != 0), (*new_asn != 0)))
            .or_insert(0) += num_reassigned;
        let old_asn_str = if *old_asn == 0 {
            "unassigned".to_string()
        } else {
            format!("AS{old_asn}")
        };
        let new_asn_str = if *new_asn == 0 {
            "unassigned".to_string()
        } else {
            format!("AS{new_asn}")
        };
        let opt = if show_addresses {
            format!(": {}", reassigned_addrs.join(", "))
        } else {
            String::new()
        };
        println!(
            "{num_reassigned} address(es) reassigned from {old_asn_str} to {new_asn_str}{opt}"
        );
    }
    let num_reassignments: usize = reassignments.iter().map(|(_, addrs)| addrs.len()).sum();
    let share = if addrs.is_empty() {
        0.0
    } else {
        num_reassignments as f64 / addrs.len() as f64
    };
    println!(
        "Summary: {num_reassignments} ({:.2}%) of {} addresses were reassigned (migrations={}, assignments={}, unassignments={})",
        share * 100.0,
        addrs.len(),
        num_reassignment_type
            .get(&(true, true))
            .copied()
            .unwrap_or(0),
        num_reassignment_type
            .get(&(false, true))
            .copied()
            .unwrap_or(0),
        num_reassignment_type
            .get(&(true, false))
            .copied()
            .unwrap_or(0),
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmapEntry {
    pub ip_prefix: String,
    pub asn: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmapClaim {
    pub epoch: u64,
    pub sender_id: String,
    pub claim_hash: String,
    pub entries: Vec<AsmapEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimObservation {
    pub epoch: u64,
    pub source_peer_id: String,
    pub sender_id: String,
    pub claim_hash: String,
    pub accepted: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusEntry {
    pub ip_prefix: String,
    pub asn: u32,
    pub votes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusArtifact {
    pub epoch: u64,
    pub topic: String,
    pub local_peer_id: String,
    pub threshold: usize,
    pub participants: Vec<String>,
    pub accepted_claims: usize,
    pub rejected_claims: BTreeMap<String, usize>,
    pub entries: Vec<ConsensusEntry>,
    pub observations: Vec<ClaimObservation>,
    pub map: ASMap,
}

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub struct QuorumEngine {
    threshold: usize,
    epoch: u64,
    seen_senders: HashSet<String>,
    votes: HashMap<(String, u32), usize>,
    observations: Vec<ClaimObservation>,
    accepted_claims: usize,
    rejected_claims: BTreeMap<String, usize>,
}

impl QuorumEngine {
    pub fn new(threshold: usize, epoch: u64) -> Self {
        Self {
            threshold,
            epoch,
            seen_senders: HashSet::new(),
            votes: HashMap::new(),
            observations: Vec::new(),
            accepted_claims: 0,
            rejected_claims: BTreeMap::new(),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn advance_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
        self.seen_senders.clear();
        self.votes.clear();
        self.observations.clear();
        self.accepted_claims = 0;
        self.rejected_claims.clear();
    }

    fn record_rejection(
        &mut self,
        epoch: u64,
        source_peer_id: String,
        sender_id: String,
        claim_hash: String,
        reason: &str,
    ) {
        self.observations.push(ClaimObservation {
            epoch,
            source_peer_id,
            sender_id,
            claim_hash,
            accepted: false,
            reason: reason.to_string(),
        });
        *self.rejected_claims.entry(reason.to_string()).or_insert(0) += 1;
    }

    pub fn process_claim(&mut self, claim: AsmapClaim) -> bool {
        let Ok(source) = claim.sender_id.parse::<PeerId>() else {
            return false;
        };
        self.process_claim_from_peer(claim, &source)
    }

    pub fn process_claim_from_peer(&mut self, claim: AsmapClaim, source: &PeerId) -> bool {
        let sender_id = claim.sender_id.clone();
        let source_peer_id = source.to_string();
        let expected_hash = claim_hash(claim.epoch, &claim.sender_id, &claim.entries);
        if claim.epoch < self.epoch {
            self.record_rejection(
                self.epoch,
                source_peer_id,
                sender_id,
                expected_hash,
                "stale_epoch",
            );
            return false;
        }
        if claim.epoch > self.epoch {
            self.advance_epoch(claim.epoch);
        }
        if sender_id != source_peer_id {
            self.record_rejection(
                self.epoch,
                source_peer_id,
                sender_id,
                expected_hash,
                "source_mismatch",
            );
            return false;
        }
        if claim.claim_hash != expected_hash {
            self.record_rejection(
                self.epoch,
                source_peer_id,
                sender_id,
                expected_hash,
                "claim_hash_mismatch",
            );
            return false;
        }
        if !self.seen_senders.insert(sender_id.clone()) {
            self.record_rejection(
                self.epoch,
                source_peer_id,
                sender_id,
                expected_hash,
                "duplicate_sender",
            );
            return false;
        }
        for entry in claim.entries {
            *self.votes.entry((entry.ip_prefix, entry.asn)).or_insert(0) += 1;
        }
        self.observations.push(ClaimObservation {
            epoch: self.epoch,
            source_peer_id,
            sender_id,
            claim_hash: expected_hash,
            accepted: true,
            reason: String::from("accepted"),
        });
        self.accepted_claims += 1;
        self.seen_senders.len() >= self.threshold
    }

    pub fn finalize(&self, topic: &str, local_peer_id: &str) -> ConsensusArtifact {
        let mut best_by_prefix: HashMap<String, (u32, usize)> = HashMap::new();
        for ((prefix, asn), count) in &self.votes {
            if *count < self.threshold {
                continue;
            }
            best_by_prefix
                .entry(prefix.clone())
                .and_modify(|best| {
                    if *count > best.1 || (*count == best.1 && *asn < best.0) {
                        *best = (*asn, *count);
                    }
                })
                .or_insert((*asn, *count));
        }

        let mut state = ASMap::new();
        let mut entries = Vec::new();
        let mut report_entries = Vec::new();
        for (prefix, (asn, votes)) in best_by_prefix {
            if let Ok((ip, prefix_len)) = parse_network_prefix(&prefix) {
                entries.push((ip_to_bits(ip, prefix_len), asn));
            }
            report_entries.push(ConsensusEntry {
                ip_prefix: prefix,
                asn,
                votes,
            });
        }
        state.update_multi(entries);
        report_entries.sort_by(|a, b| {
            b.votes
                .cmp(&a.votes)
                .then_with(|| a.ip_prefix.cmp(&b.ip_prefix))
                .then_with(|| a.asn.cmp(&b.asn))
        });
        let mut participants = self.seen_senders.iter().cloned().collect::<Vec<_>>();
        participants.sort();
        ConsensusArtifact {
            epoch: self.epoch,
            topic: topic.to_string(),
            local_peer_id: local_peer_id.to_string(),
            threshold: self.threshold,
            participants,
            accepted_claims: self.accepted_claims,
            rejected_claims: self.rejected_claims.clone(),
            entries: report_entries,
            observations: self.observations.clone(),
            map: state,
        }
    }
}

fn asmap_to_claim(state: &ASMap, epoch: u64, sender_id: String) -> AsmapClaim {
    let entries: Vec<AsmapEntry> = state
        .to_entries(false, false)
        .into_iter()
        .map(|(prefix, asn)| AsmapEntry {
            ip_prefix: bits_to_network(&prefix),
            asn,
        })
        .collect();
    let claim_hash = claim_hash(epoch, &sender_id, &entries);
    AsmapClaim {
        epoch,
        sender_id,
        claim_hash,
        entries,
    }
}

struct ServeConfig {
    input: Option<String>,
    output: Option<String>,
    threshold: usize,
    epoch: u64,
    epoch_secs: u64,
    topic: String,
}

struct CollectConfig {
    output: Option<String>,
    threshold: usize,
    epoch: u64,
    epoch_secs: u64,
    refresh_secs: u64,
    topic: String,
    collectors: Vec<u32>,
}

struct ReplayConfig {
    claims: String,
    output: String,
    report: String,
    threshold: usize,
    epoch: Option<u64>,
    topic: String,
    local_peer_id: String,
}

struct ImportConfig {
    inputs: Vec<String>,
    output: String,
    epoch: u64,
    sender_prefix: String,
}

fn parse_serve_args(args: &[String]) -> Result<ServeConfig> {
    let mut input = None;
    let mut output = None;
    let mut threshold = 3usize;
    let mut epoch = 1u64;
    let mut epoch_secs = 60u64;
    let mut topic = String::from("bitcoin-asmap-quorum");
    let mut positionals = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-t" | "--threshold" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                threshold = value
                    .parse()
                    .with_context(|| format!("invalid threshold '{value}'"))?;
            }
            "-e" | "--epoch" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                epoch = value
                    .parse()
                    .with_context(|| format!("invalid epoch '{value}'"))?;
            }
            "--epoch-secs" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                epoch_secs = value
                    .parse()
                    .with_context(|| format!("invalid epoch-secs '{value}'"))?;
            }
            "--topic" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                topic = value.to_string();
            }
            _ => positionals.push(arg.clone()),
        }
    }

    if let Some(v) = positionals.first() {
        input = Some(v.clone());
    }
    if let Some(v) = positionals.get(1) {
        output = Some(v.clone());
    }

    Ok(ServeConfig {
        input,
        output,
        threshold,
        epoch,
        epoch_secs,
        topic,
    })
}

fn parse_collect_args(args: &[String]) -> Result<CollectConfig> {
    let mut output = None;
    let mut threshold = 3usize;
    let mut epoch = 1u64;
    let mut epoch_secs = 60u64;
    let mut refresh_secs = 1800u64;
    let mut topic = String::from("bitcoin-ris-collection");
    let mut collectors: Vec<u32> = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-t" | "--threshold" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                threshold = value
                    .parse()
                    .with_context(|| format!("invalid threshold '{value}'"))?;
            }
            "-e" | "--epoch" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                epoch = value
                    .parse()
                    .with_context(|| format!("invalid epoch '{value}'"))?;
            }
            "--epoch-secs" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                epoch_secs = value
                    .parse()
                    .with_context(|| format!("invalid epoch-secs '{value}'"))?;
            }
            "--refresh-secs" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                refresh_secs = value
                    .parse()
                    .with_context(|| format!("invalid refresh-secs '{value}'"))?;
            }
            "--topic" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                topic = value.to_string();
            }
            "-o" | "--output" => {
                output = Some(
                    iter.next()
                        .ok_or_else(|| anyhow!("missing value for {arg}"))?
                        .to_string(),
                );
            }
            "-n" | "--ripe_collector_number" | "--collectors" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                collectors.extend(
                    value
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(|s| {
                            s.parse()
                                .with_context(|| format!("invalid collector list '{value}'"))
                        })
                        .collect::<Result<Vec<u32>>>()?,
                );
            }
            _ => {}
        }
    }

    Ok(CollectConfig {
        output,
        threshold,
        epoch,
        epoch_secs,
        refresh_secs,
        topic,
        collectors,
    })
}

async fn run_serve_async(args: &[String]) -> Result<()> {
    let cfg = parse_serve_args(args)?;
    info!(
        target: "asmap::serve",
        "starting serve mode topic={} threshold={} epoch={} epoch_secs={}",
        cfg.topic, cfg.threshold, cfg.epoch, cfg.epoch_secs
    );
    let input_name = cfg.input.as_deref().unwrap_or("<stdin>");
    let state = load_file(open_input(cfg.input.as_deref())?, input_name)?;
    let local_claim_template = asmap_to_claim(&state, cfg.epoch, String::new());
    let output_path = cfg
        .output
        .clone()
        .unwrap_or_else(|| "asmap.map".to_string());
    let report_path = {
        let path = Path::new(&output_path);
        let mut buf = PathBuf::from(path);
        buf.set_extension("json");
        buf
    };

    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(StdDuration::from_secs(1))
                .build()
                .map_err(std::io::Error::other)?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;

            Ok(AppBehaviour { gossipsub, mdns })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(StdDuration::from_secs(60)))
        .build();

    let topic_name = cfg.topic.clone();
    let topic = gossipsub::IdentTopic::new(topic_name.clone());
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut engine = QuorumEngine::new(cfg.threshold, cfg.epoch);
    let mut publish_timer = interval(StdDuration::from_secs(5));
    let mut epoch_timer = interval(StdDuration::from_secs(cfg.epoch_secs));
    let local_peer_id = swarm.local_peer_id().to_string();
    let mut local_claim = local_claim_template;
    local_claim.sender_id = local_peer_id.clone();
    local_claim.epoch = engine.epoch();
    local_claim.claim_hash = claim_hash(
        local_claim.epoch,
        &local_claim.sender_id,
        &local_claim.entries,
    );
    let mut consensus_written = false;

    loop {
        tokio::select! {
            _ = publish_timer.tick() => {
                trace!(target: "asmap::serve", "publishing local claim for epoch {}", engine.epoch());
                local_claim.epoch = engine.epoch();
                local_claim.claim_hash = claim_hash(local_claim.epoch, &local_claim.sender_id, &local_claim.entries);
                let encoded = serde_json::to_vec(&local_claim)?;
                let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), encoded);
            }
            _ = epoch_timer.tick() => {
                let next_epoch = engine.epoch() + 1;
                engine.advance_epoch(next_epoch);
                local_claim.epoch = next_epoch;
                local_claim.claim_hash = claim_hash(local_claim.epoch, &local_claim.sender_id, &local_claim.entries);
                consensus_written = false;
                info!(target: "asmap::serve", "advancing to epoch {next_epoch}");
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    debug!(target: "asmap::serve", "discovered {} mdns peers", list.len());
                    for (peer_id, _multiaddr) in list {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                }

                SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                    trace!(
                        target: "asmap::serve",
                        "received gossip message from {} ({} bytes)",
                        propagation_source,
                        message.data.len()
                    );
                    if let Ok(claim) = serde_json::from_slice::<AsmapClaim>(&message.data)
                        && engine.process_claim_from_peer(claim, &propagation_source)
                        && !consensus_written
                    {
                        let artifact = engine.finalize(&topic_name, &local_peer_id);
                        save_binary(
                            open_output(Some(output_path.as_str()), true)?,
                            &artifact.map,
                            false,
                            output_path.as_str(),
                        )?;
                        save_json_report(&report_path, &artifact)?;
                        info!(
                            target: "asmap::serve",
                            "quorum reached for epoch {}. wrote consensus ASMap to {} and {}",
                            engine.epoch(),
                            output_path,
                            report_path.display()
                        );
                        consensus_written = true;
                    }
                }
                _ => {}
            }
        }
    }
}

fn collect_ris_state(collectors: &[u32]) -> Result<ASMap> {
    let bottleneck = FindBottleneck::from_collectors(collectors)?;
    Ok(bottleneck.to_asmap())
}

async fn build_ris_claim(
    collectors: Vec<u32>,
    epoch: u64,
    sender_id: String,
) -> Result<AsmapClaim> {
    let state = tokio::task::spawn_blocking(move || collect_ris_state(&collectors))
        .await
        .map_err(|err| anyhow!("collector task failed: {err}"))??;
    Ok(asmap_to_claim(&state, epoch, sender_id))
}

async fn run_collect_async(args: &[String]) -> Result<()> {
    let cfg = parse_collect_args(args)?;
    info!(
        target: "asmap::collect",
        "starting collect mode topic={} threshold={} epoch={} epoch_secs={} refresh_secs={}",
        cfg.topic, cfg.threshold, cfg.epoch, cfg.epoch_secs, cfg.refresh_secs
    );
    let output_path = cfg
        .output
        .clone()
        .unwrap_or_else(|| "ris-asmap.map".to_string());
    let report_path = {
        let path = Path::new(&output_path);
        let mut buf = PathBuf::from(path);
        buf.set_extension("json");
        buf
    };

    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(StdDuration::from_secs(1))
                .build()
                .map_err(std::io::Error::other)?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;

            Ok(AppBehaviour { gossipsub, mdns })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(StdDuration::from_secs(60)))
        .build();

    let topic_name = cfg.topic.clone();
    let topic = gossipsub::IdentTopic::new(topic_name.clone());
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut engine = QuorumEngine::new(cfg.threshold, cfg.epoch);
    let mut publish_timer = interval(StdDuration::from_secs(5));
    let mut refresh_timer = interval(StdDuration::from_secs(cfg.refresh_secs));
    let mut epoch_timer = interval(StdDuration::from_secs(cfg.epoch_secs));
    let local_peer_id = swarm.local_peer_id().to_string();
    let local_claim_template =
        build_ris_claim(cfg.collectors.clone(), cfg.epoch, local_peer_id.clone()).await?;
    let mut local_claim = local_claim_template;
    local_claim.sender_id = local_peer_id.clone();
    local_claim.epoch = engine.epoch();
    local_claim.claim_hash = claim_hash(
        local_claim.epoch,
        &local_claim.sender_id,
        &local_claim.entries,
    );
    let mut consensus_written = false;

    loop {
        tokio::select! {
            _ = publish_timer.tick() => {
                trace!(target: "asmap::collect", "publishing local RIS claim for epoch {}", engine.epoch());
                local_claim.epoch = engine.epoch();
                local_claim.claim_hash = claim_hash(local_claim.epoch, &local_claim.sender_id, &local_claim.entries);
                let encoded = serde_json::to_vec(&local_claim)?;
                let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), encoded);
            }
            _ = refresh_timer.tick() => {
                debug!(target: "asmap::collect", "refreshing RIS snapshot for epoch {}", engine.epoch());
                match build_ris_claim(cfg.collectors.clone(), engine.epoch(), local_peer_id.clone()).await {
                    Ok(mut refreshed) => {
                        refreshed.sender_id = local_peer_id.clone();
                        refreshed.epoch = engine.epoch();
                        refreshed.claim_hash = claim_hash(refreshed.epoch, &refreshed.sender_id, &refreshed.entries);
                        local_claim = refreshed;
                        info!(target: "asmap::collect", "refreshed RIS snapshot for epoch {}", engine.epoch());
                    }
                    Err(err) => {
                        warn!(target: "asmap::collect", "failed to refresh RIS snapshot: {err:#}");
                    }
                }
            }
            _ = epoch_timer.tick() => {
                let next_epoch = engine.epoch() + 1;
                engine.advance_epoch(next_epoch);
                consensus_written = false;
                info!(target: "asmap::collect", "advancing to epoch {next_epoch}");
                match build_ris_claim(cfg.collectors.clone(), next_epoch, local_peer_id.clone()).await {
                    Ok(mut refreshed) => {
                        refreshed.sender_id = local_peer_id.clone();
                        refreshed.epoch = next_epoch;
                        refreshed.claim_hash = claim_hash(refreshed.epoch, &refreshed.sender_id, &refreshed.entries);
                        local_claim = refreshed;
                    }
                    Err(err) => {
                        warn!(target: "asmap::collect", "failed to refresh RIS snapshot for epoch {next_epoch}: {err:#}");
                    }
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    debug!(target: "asmap::collect", "discovered {} mdns peers", list.len());
                    for (peer_id, _multiaddr) in list {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                    trace!(
                        target: "asmap::collect",
                        "received gossip message from {} ({} bytes)",
                        propagation_source,
                        message.data.len()
                    );
                    if let Ok(claim) = serde_json::from_slice::<AsmapClaim>(&message.data)
                        && engine.process_claim_from_peer(claim, &propagation_source)
                        && !consensus_written
                    {
                        let artifact = engine.finalize(&topic_name, &local_peer_id);
                        save_binary(
                            open_output(Some(output_path.as_str()), true)?,
                            &artifact.map,
                            false,
                            output_path.as_str(),
                        )?;
                        save_json_report(&report_path, &artifact)?;
                        info!(
                            target: "asmap::collect",
                            "RIS quorum reached for epoch {}. wrote consensus ASMap to {} and {}",
                            engine.epoch(),
                            output_path,
                            report_path.display()
                        );
                        consensus_written = true;
                    }
                }
                _ => {}
            }
        }
    }
}

fn parse_replay_args(args: &[String]) -> Result<ReplayConfig> {
    let mut claims = None;
    let mut output = String::from("asmap.map");
    let mut report = String::from("asmap.json");
    let mut threshold = 3usize;
    let mut epoch = None;
    let mut topic = String::from("bitcoin-asmap-quorum");
    let mut local_peer_id = String::from("offline-replay");
    let mut positionals = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-t" | "--threshold" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                threshold = value
                    .parse()
                    .with_context(|| format!("invalid threshold '{value}'"))?;
            }
            "-e" | "--epoch" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                epoch = Some(
                    value
                        .parse()
                        .with_context(|| format!("invalid epoch '{value}'"))?,
                );
            }
            "-o" | "--output" => {
                output = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?
                    .to_string();
            }
            "--report" => {
                report = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?
                    .to_string();
            }
            "--topic" => {
                topic = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?
                    .to_string();
            }
            "--local-peer-id" => {
                local_peer_id = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?
                    .to_string();
            }
            _ => positionals.push(arg.clone()),
        }
    }

    if let Some(v) = positionals.first() {
        claims = Some(v.clone());
    }

    Ok(ReplayConfig {
        claims: claims.ok_or_else(|| anyhow!("replay requires a claims file"))?,
        output,
        report,
        threshold,
        epoch,
        topic,
        local_peer_id,
    })
}

fn parse_import_args(args: &[String]) -> Result<ImportConfig> {
    let mut inputs = Vec::new();
    let mut output = String::from("claims.json");
    let mut epoch = 1u64;
    let mut sender_prefix = String::from("snapshot");

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-o" | "--output" => {
                output = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?
                    .to_string();
            }
            "-e" | "--epoch" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                epoch = value
                    .parse()
                    .with_context(|| format!("invalid epoch '{value}'"))?;
            }
            "--sender-prefix" => {
                sender_prefix = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?
                    .to_string();
            }
            _ => inputs.push(arg.clone()),
        }
    }

    if inputs.is_empty() {
        bail!("import requires at least one snapshot input file");
    }

    Ok(ImportConfig {
        inputs,
        output,
        epoch,
        sender_prefix,
    })
}

fn snapshot_sender_id(prefix: &str, path: &str, idx: usize) -> String {
    let stem = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("snapshot");
    format!("{prefix}-{stem}-{idx}")
}

fn run_import(args: &[String]) -> Result<()> {
    let cfg = parse_import_args(args)?;
    let mut claims = Vec::new();
    for (idx, input) in cfg.inputs.iter().enumerate() {
        let state = load_file(open_input(Some(input))?, input)?;
        let sender_id = snapshot_sender_id(&cfg.sender_prefix, input, idx);
        claims.push(asmap_to_claim(&state, cfg.epoch, sender_id));
    }

    let output_file = File::create(&cfg.output)
        .with_context(|| format!("Output file '{}' cannot be written to", cfg.output))?;
    serde_json::to_writer_pretty(output_file, &claims)?;
    println!(
        "[+] Imported {} snapshot(s) into {}",
        claims.len(),
        cfg.output
    );
    Ok(())
}

fn run_compare_reports(args: &[String]) -> Result<()> {
    let mut pos = Vec::new();
    for arg in args {
        pos.push(arg.clone());
    }
    if pos.len() != 2 {
        bail!("compare requires two report files");
    }
    let left = load_json_report(&pos[0])?;
    let right = load_json_report(&pos[1])?;
    let left_map = left.map.clone();
    let right_map = right.map.clone();
    let mut changed = left_map.diff(&right_map);
    changed.sort_by(|a, b| a.0.cmp(&b.0));
    for (prefix, old_asn, new_asn) in changed {
        println!(
            "{} AS{} -> AS{}",
            bits_to_network(&prefix),
            old_asn,
            new_asn
        );
    }
    println!(
        "[+] Compared {} vs {}: {} changed prefix(es)",
        pos[0],
        pos[1],
        left_map.diff(&right_map).len()
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
struct RoutingPrefix {
    ip: IpAddr,
    mask: u8,
}

impl std::fmt::Display for RoutingPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.mask)
    }
}

impl std::str::FromStr for RoutingPrefix {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let (ip_str, mask_str) = text
            .split_once('/')
            .ok_or_else(|| anyhow!("invalid prefix '{text}'"))?;
        let ip = ip_str
            .parse::<IpAddr>()
            .with_context(|| format!("invalid address '{ip_str}'"))?;
        let mask = mask_str
            .parse::<u8>()
            .with_context(|| format!("invalid prefix '{text}'"))?;
        Ok(Self { ip, mask })
    }
}

struct AsPathParser<'buffer> {
    buffer: &'buffer [u8],
    next: usize,
}

impl<'buffer> AsPathParser<'buffer> {
    fn parse(buffer: &'buffer [u8]) -> Result<Vec<u32>> {
        if buffer.is_empty() {
            bail!("missing MRT attributes");
        }
        Self::new(buffer).parse_attributes()
    }

    fn new(buffer: &'buffer [u8]) -> Self {
        Self { buffer, next: 0 }
    }

    fn advance(&mut self) -> Result<u8> {
        if self.next >= self.buffer.len() {
            bail!("unexpected end of MRT attribute buffer");
        }
        let byte = self.buffer[self.next];
        self.next += 1;
        Ok(byte)
    }

    fn parse_u32(&mut self) -> Result<u32> {
        let a = self.advance()?;
        let b = self.advance()?;
        let c = self.advance()?;
        let d = self.advance()?;
        Ok(u32::from_be_bytes([a, b, c, d]))
    }

    fn parse_attributes(mut self) -> Result<Vec<u32>> {
        let mut paths = Vec::new();
        while self.next < self.buffer.len() {
            if let Some(path) = self.parse_attribute()? {
                if path.is_empty() {
                    bail!("MRT attribute had no AS path");
                }
                paths.push(path);
            }
        }
        if paths.len() > 1 {
            bail!("MRT entry contained multiple AS paths");
        }
        paths
            .pop()
            .ok_or_else(|| anyhow!("MRT entry had no AS path"))
    }

    fn parse_attribute(&mut self) -> Result<Option<Vec<u32>>> {
        let flag = self.advance()?;
        let type_code = self.advance()?;
        let mut attribute_length: u16 = self.advance()?.into();
        if (flag >> 4) & 1 == 1 {
            attribute_length = (attribute_length << 8) | self.advance()? as u16;
        }

        if type_code == 2 {
            let end = self.next + attribute_length as usize;
            let asn_path = self.parse_as_path();
            let remaining = end.saturating_sub(self.next);
            for _ in 0..remaining {
                let _ = self.advance()?;
            }
            asn_path
        } else {
            for _ in 0..attribute_length {
                let _ = self.advance()?;
            }
            Ok(None)
        }
    }

    fn parse_as_path(&mut self) -> Result<Option<Vec<u32>>> {
        let as_set_indicator = self.advance()?;
        match as_set_indicator {
            1 => {
                let num_asn = self.advance()?;
                for _ in 0..num_asn {
                    let _ = self.parse_u32()?;
                }
                Ok(None)
            }
            2 => {
                let mut as_path = Vec::new();
                let num_asn = self.advance()?;
                for _ in 0..num_asn {
                    as_path.push(self.parse_u32()?);
                }
                Ok(Some(as_path))
            }
            _ => bail!("unknown AS path type {}", as_set_indicator),
        }
    }
}

#[derive(Debug, PartialEq)]
struct FindBottleneck {
    prefix_asn: HashMap<RoutingPrefix, u32>,
}

impl FindBottleneck {
    fn from_collectors(collectors: &[u32]) -> Result<Self> {
        let mut mrt_hm = HashMap::new();
        let targets: Vec<u32> = if collectors.is_empty() {
            (0..=24).collect()
        } else {
            collectors.to_vec()
        };
        for number in targets {
            let url = format!("http://data.ris.ripe.net/rrc{:02}/latest-bview.gz", number);
            info!(target: "asmap::collect", "collecting from {url}");
            let res = reqwest::blocking::get(&url)
                .with_context(|| format!("failed request for {url}"))?;
            let mut decoder = flate2::read::GzDecoder::new(res);
            Self::parse_mrt(&mut decoder, &mut mrt_hm)?;
            debug!(target: "asmap::collect", "collected {url}");
        }
        let mut bottleneck = FindBottleneck {
            prefix_asn: HashMap::new(),
        };
        bottleneck.find_as_bottleneck(&mut mrt_hm)?;
        Ok(bottleneck)
    }

    fn locate(dir: &PathBuf) -> Result<Self> {
        info!(target: "asmap::find_bottleneck", "locating bottlenecks in {}", dir.display());
        let mut mrt_hm = HashMap::new();
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)
                .with_context(|| format!("cannot read directory '{}'", dir.display()))?
            {
                let path = entry?.path();
                debug!(target: "asmap::find_bottleneck", "parsing {}", path.display());
                let buffer = std::io::BufReader::new(
                    File::open(&path)
                        .with_context(|| format!("cannot open '{}'", path.display()))?,
                );
                let mut decoder = flate2::read::GzDecoder::new(buffer);
                Self::parse_mrt(&mut decoder, &mut mrt_hm)?;
            }
        }
        let mut bottleneck = FindBottleneck {
            prefix_asn: HashMap::new(),
        };
        bottleneck.find_as_bottleneck(&mut mrt_hm)?;
        Ok(bottleneck)
    }

    fn to_asmap(&self) -> ASMap {
        let mut state = ASMap::new();
        let mut entries = Vec::new();
        for (prefix, asn) in &self.prefix_asn {
            entries.push((ip_to_bits(prefix.ip, prefix.mask), *asn));
        }
        state.update_multi(entries);
        state
    }

    fn find_as_bottleneck(
        &mut self,
        mrt_hm: &mut HashMap<RoutingPrefix, Vec<Vec<u32>>>,
    ) -> Result<()> {
        let mut prefix_to_common_suffix: HashMap<RoutingPrefix, Vec<u32>> = HashMap::new();
        Self::find_common_suffix(mrt_hm, &mut prefix_to_common_suffix)?;
        for (prefix, as_path) in prefix_to_common_suffix {
            if let Some(asn) = as_path.first() {
                self.prefix_asn.insert(prefix, *asn);
            }
        }
        Ok(())
    }

    fn find_common_suffix(
        mrt_hm: &mut HashMap<RoutingPrefix, Vec<Vec<u32>>>,
        prefix_to_common_suffix: &mut HashMap<RoutingPrefix, Vec<u32>>,
    ) -> Result<()> {
        for (prefix, as_paths) in mrt_hm.iter() {
            let mut as_paths_sorted: Vec<&Vec<u32>> = as_paths.iter().collect();
            as_paths_sorted.sort_by_key(|path| path.len());
            if as_paths_sorted.is_empty() {
                continue;
            }
            let mut rev_common_suffix: Vec<u32> = as_paths_sorted[0].clone();
            rev_common_suffix.reverse();
            for as_path in as_paths_sorted.iter().skip(1) {
                let mut rev_as_path: Vec<u32> = (*as_path).clone();
                rev_as_path.reverse();
                if rev_common_suffix.first() != rev_as_path.first() {
                    continue;
                }
                for i in 1..rev_common_suffix.len().min(rev_as_path.len()) {
                    if rev_as_path[i] != rev_common_suffix[i] {
                        rev_common_suffix.truncate(i);
                        break;
                    }
                }
            }
            rev_common_suffix.reverse();
            prefix_to_common_suffix.insert(*prefix, rev_common_suffix);
        }
        Ok(())
    }

    fn parse_mrt(
        reader: &mut dyn Read,
        mrt_hm: &mut HashMap<RoutingPrefix, Vec<Vec<u32>>>,
    ) -> Result<()> {
        let mut reader = mrt_rs::Reader { stream: reader };
        loop {
            match reader.read() {
                Ok(Some((_, record))) => {
                    if let mrt_rs::Record::TABLE_DUMP_V2(tdv2_entry) = record {
                        match tdv2_entry {
                            mrt_rs::tabledump::TABLE_DUMP_V2::RIB_IPV4_UNICAST(entry) => {
                                trace!(target: "asmap::mrt", "ipv4 prefix len={} bytes={}", entry.prefix_length, entry.prefix.len());
                                let ip = Self::format_ip(&entry.prefix, true)?;
                                Self::match_rib_entry(
                                    entry.entries,
                                    ip,
                                    entry.prefix_length,
                                    mrt_hm,
                                )?;
                            }
                            mrt_rs::tabledump::TABLE_DUMP_V2::RIB_IPV6_UNICAST(entry) => {
                                trace!(target: "asmap::mrt", "ipv6 prefix len={} bytes={}", entry.prefix_length, entry.prefix.len());
                                let ip = Self::format_ip(&entry.prefix, false)?;
                                Self::match_rib_entry(
                                    entry.entries,
                                    ip,
                                    entry.prefix_length,
                                    mrt_hm,
                                )?;
                            }
                            _ => {}
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        Ok(())
    }

    fn format_ip(ip: &[u8], is_ipv4: bool) -> Result<IpAddr> {
        if is_ipv4 {
            if ip.len() > 4 {
                bail!("invalid IPv4 prefix bytes");
            }
            let mut bytes = [0u8; 4];
            bytes[..ip.len()].copy_from_slice(ip);
            Ok(IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        } else {
            if ip.len() > 16 {
                bail!("invalid IPv6 prefix bytes");
            }
            let mut bytes = [0u8; 16];
            bytes[..ip.len()].copy_from_slice(ip);
            Ok(IpAddr::V6(std::net::Ipv6Addr::new(
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                u16::from_be_bytes([bytes[4], bytes[5]]),
                u16::from_be_bytes([bytes[6], bytes[7]]),
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
            )))
        }
    }

    fn match_rib_entry(
        entries: Vec<mrt_rs::records::tabledump::RIBEntry>,
        ip: IpAddr,
        mask: u8,
        mrt_hm: &mut HashMap<RoutingPrefix, Vec<Vec<u32>>>,
    ) -> Result<()> {
        let routing_prefix = RoutingPrefix { ip, mask };
        for rib_entry in entries {
            if let Ok(mut as_path) = AsPathParser::parse(&rib_entry.attributes) {
                as_path.dedup();
                trace!(target: "asmap::mrt", "prefix {} path {:?}", routing_prefix, as_path);
                mrt_hm.entry(routing_prefix).or_default().push(as_path);
            }
        }
        Ok(())
    }

    fn write(self, out: Option<&Path>) -> Result<()> {
        if let Some(path) = out {
            let epoch = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                .as_secs();
            let dst = path.join(format!("bottleneck.{epoch}.txt"));
            let mut file =
                File::create(&dst).with_context(|| format!("cannot create '{}'", dst.display()))?;
            self.write_bottleneck(&mut file)?;
        } else {
            self.write_bottleneck(&mut io::stdout())?;
        }
        Ok(())
    }

    fn write_bottleneck(self, out: &mut dyn Write) -> Result<()> {
        for (key, value) in self.prefix_asn {
            writeln!(out, "{key} AS{value}")?;
        }
        Ok(())
    }
}

fn parse_download_args(args: &[String]) -> Result<(PathBuf, Vec<u32>)> {
    let mut out = PathBuf::from("dump");
    let mut collectors: Vec<u32> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-o" | "--out" => {
                out = PathBuf::from(
                    iter.next()
                        .ok_or_else(|| anyhow!("missing value for {arg}"))?,
                );
            }
            "-n" | "--ripe_collector_number" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                collectors.extend(
                    raw.split(',')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.parse::<u32>())
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .with_context(|| format!("invalid collector list '{raw}'"))?,
                );
            }
            _ => {}
        }
    }
    Ok((out, collectors))
}

fn run_download(args: &[String]) -> Result<()> {
    let (out, collectors) = parse_download_args(args)?;
    std::fs::create_dir_all(&out)
        .with_context(|| format!("cannot create directory '{}'", out.display()))?;
    let targets: Vec<u32> = if collectors.is_empty() {
        (0..=24).collect()
    } else {
        collectors
    };
    for number in targets {
        let url = format!("http://data.ris.ripe.net/rrc{:02}/latest-bview.gz", number);
        info!(target: "asmap::download", "downloading {url}");
        let mut res =
            reqwest::blocking::get(&url).with_context(|| format!("failed request for {url}"))?;
        let dst = out.join(format!("rrc{:02}-latest-bview.gz", number));
        let file =
            File::create(&dst).with_context(|| format!("cannot create '{}'", dst.display()))?;
        let mut buf_write = std::io::BufWriter::new(file);
        std::io::copy(&mut res, &mut buf_write)?;
        info!(target: "asmap::download", "downloaded {url} -> {}", dst.display());
    }
    Ok(())
}

fn parse_find_bottleneck_args(args: &[String]) -> Result<(PathBuf, Option<PathBuf>)> {
    let mut dir = None;
    let mut out = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-d" | "--dir" => {
                dir = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| anyhow!("missing value for {arg}"))?,
                ));
            }
            "-o" | "--out" => {
                out = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| anyhow!("missing value for {arg}"))?,
                ));
            }
            _ => {}
        }
    }
    Ok((
        dir.ok_or_else(|| anyhow!("find-bottleneck requires --dir"))?,
        out,
    ))
}

fn run_find_bottleneck(args: &[String]) -> Result<()> {
    let (dir, out) = parse_find_bottleneck_args(args)?;
    info!(target: "asmap::find_bottleneck", "reading MRT files from {}", dir.display());
    let bottleneck = FindBottleneck::locate(&dir)?;
    bottleneck.write(out.as_deref())?;
    info!(target: "asmap::find_bottleneck", "bottleneck extraction complete");
    Ok(())
}

fn run_replay(args: &[String]) -> Result<()> {
    let cfg = parse_replay_args(args)?;
    info!(target: "asmap::replay", "replaying claims from {} at epoch {:?}", cfg.claims, cfg.epoch);
    let claims = load_claims(&cfg.claims)?;
    if claims.is_empty() {
        bail!("replay input contains no claims");
    }
    let epoch = cfg.epoch.unwrap_or(claims[0].epoch);
    let mut engine = QuorumEngine::new(cfg.threshold, epoch);
    for claim in claims {
        let _ = engine.process_claim(claim);
    }
    let artifact = engine.finalize(&cfg.topic, &cfg.local_peer_id);
    save_binary(
        open_output(Some(cfg.output.as_str()), true)?,
        &artifact.map,
        false,
        &cfg.output,
    )?;
    save_json_report(Path::new(&cfg.report), &artifact)?;
    info!(
        target: "asmap::replay",
        "replayed {} claims ({} accepted) into {} and {}",
        artifact.observations.len(),
        artifact.accepted_claims,
        cfg.output,
        cfg.report
    );
    Ok(())
}

fn usage() {
    eprintln!(
        "Usage:\n  asmap encode [-f|--fill] [infile] [outfile]\n  asmap decode [-f|--fill] [-n|--nonoverlapping] [infile] [outfile]\n  asmap diff [-i|--ignore-unassigned] infile1 infile2\n  asmap diff_addrs [-s|--show-addresses] infile1 infile2 addrs_file\n  asmap import [--epoch N] [--sender-prefix PREFIX] [--output FILE] snapshot1 [snapshot2...]\n  asmap serve [--threshold N] [--epoch N] [--epoch-secs N] [--topic NAME] [infile] [outfile]\n  asmap collect [--threshold N] [--epoch N] [--epoch-secs N] [--refresh-secs N] [--topic NAME] [-n 0,1,2] [--output FILE]\n  asmap replay [--threshold N] [--epoch N] [--topic NAME] [--local-peer-id ID] [--output FILE] [--report FILE] claims.jsonl\n  asmap compare report1.json report2.json\n  asmap download [-o OUT] [-n 0,1,2]\n  asmap find-bottleneck -d DIR [-o OUT]\n  asmap verify report.json [mapfile]"
    );
}

pub fn run() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
        return Ok(());
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "encode" => run_encode(&args),
        "decode" => run_decode(&args),
        "diff" => run_diff(&args),
        "diff_addrs" | "diff-addrs" => run_diff_addrs(&args),
        "import" => run_import(&args),
        "download" => run_download(&args),
        "find-bottleneck" | "find_bottleneck" => run_find_bottleneck(&args),
        "collect" => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_collect_async(&args))
        }
        "replay" => run_replay(&args),
        "compare" => run_compare_reports(&args),
        "verify" => {
            if args.is_empty() {
                usage();
                bail!("verify requires a report file");
            }
            verify_report(&args[0], args.get(1).map(String::as_str))
        }
        "serve" => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_serve_async(&args))
        }
        _ => {
            usage();
            bail!("unknown subcommand '{cmd}'")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claim(epoch: u64, sender_id: String, entries: Vec<AsmapEntry>) -> AsmapClaim {
        let claim_hash = claim_hash(epoch, &sender_id, &entries);
        AsmapClaim {
            epoch,
            sender_id,
            claim_hash,
            entries,
        }
    }

    #[test]
    fn network_roundtrip_ipv4() {
        let bits = ip_to_bits("1.2.3.0".parse::<IpAddr>().unwrap(), 24);
        assert_eq!(bits_to_network(&bits), "1.2.3.0/24");
    }

    #[test]
    fn network_roundtrip_ipv6() {
        let bits = ip_to_bits("2001:db8::".parse::<IpAddr>().unwrap(), 32);
        assert_eq!(bits_to_network(&bits), "2001:db8::/32");
    }

    #[test]
    fn binary_roundtrip_empty() {
        let state = ASMap::new();
        let enc = state.to_binary(false);
        let dec = ASMap::from_binary(&enc).unwrap();
        assert_eq!(state, dec);
    }

    #[test]
    fn quorum_engine_dedupes_sender() {
        let mut engine = QuorumEngine::new(2, 7);
        let claim = make_claim(
            7,
            "peer-a".to_string(),
            vec![AsmapEntry {
                ip_prefix: "1.2.3.0/24".to_string(),
                asn: 64512,
            }],
        );

        assert!(!engine.process_claim(claim.clone()));
        assert!(!engine.process_claim(claim));
    }

    #[test]
    fn quorum_engine_finalizes_consensus() {
        let mut engine = QuorumEngine::new(2, 7);
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let claim_a = make_claim(
            7,
            peer_a.to_string(),
            vec![AsmapEntry {
                ip_prefix: "1.2.3.0/24".to_string(),
                asn: 64512,
            }],
        );
        let claim_b = make_claim(
            7,
            peer_b.to_string(),
            vec![AsmapEntry {
                ip_prefix: "1.2.3.0/24".to_string(),
                asn: 64512,
            }],
        );

        assert!(!engine.process_claim(claim_a));
        assert!(engine.process_claim(claim_b));
        let consensus = engine.finalize("bitcoin-asmap-quorum", &peer_a.to_string());
        assert_eq!(consensus.epoch, 7);
        assert_eq!(consensus.topic, "bitcoin-asmap-quorum");
        assert_eq!(consensus.threshold, 2);
        assert_eq!(consensus.local_peer_id, peer_a.to_string());
        assert_eq!(consensus.accepted_claims, 2);
        assert!(consensus.rejected_claims.is_empty());
        assert_eq!(consensus.entries.len(), 1);
        assert_eq!(
            consensus
                .map
                .lookup(&ip_to_bits("1.2.3.0".parse::<IpAddr>().unwrap(), 24)),
            Some(64512)
        );
    }

    #[test]
    fn quorum_engine_rejects_stale_epochs() {
        let mut engine = QuorumEngine::new(2, 7);
        let stale = make_claim(
            6,
            "peer-a".to_string(),
            vec![AsmapEntry {
                ip_prefix: "1.2.3.0/24".to_string(),
                asn: 64512,
            }],
        );
        assert!(!engine.process_claim(stale));
        assert_eq!(engine.epoch(), 7);
    }

    #[test]
    fn quorum_engine_rejects_source_mismatch() {
        let mut engine = QuorumEngine::new(2, 7);
        let source = PeerId::random();
        let claim = make_claim(
            7,
            source.to_string(),
            vec![AsmapEntry {
                ip_prefix: "1.2.3.0/24".to_string(),
                asn: 64512,
            }],
        );
        let other_source = PeerId::random();
        assert!(!engine.process_claim_from_peer(claim, &other_source));
    }

    #[test]
    fn report_verifier_rebuilds_map() {
        let claim = make_claim(
            7,
            PeerId::random().to_string(),
            vec![AsmapEntry {
                ip_prefix: "1.2.3.0/24".to_string(),
                asn: 64512,
            }],
        );
        let mut engine = QuorumEngine::new(1, 7);
        assert!(engine.process_claim(claim));
        let artifact = engine.finalize("bitcoin-asmap-quorum", &PeerId::random().to_string());
        let rebuilt = {
            let mut state = ASMap::new();
            let entries = artifact
                .entries
                .iter()
                .map(|entry| {
                    let (ip, prefix_len) = parse_network_prefix(&entry.ip_prefix).unwrap();
                    (ip_to_bits(ip, prefix_len), entry.asn)
                })
                .collect::<Vec<_>>();
            state.update_multi(entries);
            state
        };
        assert_eq!(rebuilt, artifact.map);
    }

    #[test]
    fn load_claims_supports_json_array_and_jsonl() {
        let claim_a = make_claim(
            7,
            "peer-a".to_string(),
            vec![AsmapEntry {
                ip_prefix: "1.2.3.0/24".to_string(),
                asn: 64512,
            }],
        );
        let claim_b = make_claim(
            7,
            "peer-b".to_string(),
            vec![AsmapEntry {
                ip_prefix: "1.2.3.0/24".to_string(),
                asn: 64512,
            }],
        );

        let array_path = std::env::temp_dir().join("asmap_claims_array.json");
        std::fs::write(
            &array_path,
            serde_json::to_string(&vec![claim_a.clone(), claim_b.clone()]).unwrap(),
        )
        .unwrap();
        let array_claims = load_claims(array_path.to_str().unwrap()).unwrap();
        assert_eq!(array_claims.len(), 2);

        let jsonl_path = std::env::temp_dir().join("asmap_claims.jsonl");
        std::fs::write(
            &jsonl_path,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&claim_a).unwrap(),
                serde_json::to_string(&claim_b).unwrap()
            ),
        )
        .unwrap();
        let jsonl_claims = load_claims(jsonl_path.to_str().unwrap()).unwrap();
        assert_eq!(jsonl_claims.len(), 2);
    }

    #[test]
    fn import_snapshot_roundtrips_to_claim_batch() {
        let snapshot_path = std::env::temp_dir().join("asmap_snapshot.txt");
        std::fs::write(&snapshot_path, "1.2.3.0/24 AS64512\n").unwrap();
        let state = load_file(
            open_input(Some(snapshot_path.to_str().unwrap())).unwrap(),
            snapshot_path.to_str().unwrap(),
        )
        .unwrap();
        let claim = asmap_to_claim(&state, 11, "snapshot-test-0".to_string());
        assert_eq!(claim.epoch, 11);
        assert_eq!(claim.entries.len(), 1);
        assert_eq!(claim.entries[0].ip_prefix, "1.2.3.0/24");
    }

    #[test]
    fn consensus_artifacts_compare_as_maps() {
        let claim_a = make_claim(
            7,
            PeerId::random().to_string(),
            vec![AsmapEntry {
                ip_prefix: "1.2.3.0/24".to_string(),
                asn: 64512,
            }],
        );
        let claim_b = make_claim(
            7,
            PeerId::random().to_string(),
            vec![AsmapEntry {
                ip_prefix: "1.2.3.0/24".to_string(),
                asn: 64513,
            }],
        );

        let mut engine_a = QuorumEngine::new(1, 7);
        let mut engine_b = QuorumEngine::new(1, 7);
        assert!(engine_a.process_claim(claim_a));
        assert!(engine_b.process_claim(claim_b));
        let artifact_a = engine_a.finalize("bitcoin-asmap-quorum", &PeerId::random().to_string());
        let artifact_b = engine_b.finalize("bitcoin-asmap-quorum", &PeerId::random().to_string());
        assert_ne!(artifact_a.map, artifact_b.map);
        assert_eq!(artifact_a.map.diff(&artifact_b.map).len(), 1);
    }

    #[test]
    fn bottleneck_state_converts_to_asmap() {
        let mut prefix_asn = HashMap::new();
        prefix_asn.insert(
            RoutingPrefix {
                ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0)),
                mask: 24,
            },
            64512,
        );
        let bottleneck = FindBottleneck { prefix_asn };
        let map = bottleneck.to_asmap();
        assert_eq!(
            map.lookup(&ip_to_bits(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 32)),
            Some(64512)
        );
    }
}
