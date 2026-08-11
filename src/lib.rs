use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Timelike, Utc};
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns,
    swarm::{NetworkBehaviour, SwarmEvent},
    SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::Write,
    sync::{Arc, Mutex},
    time::Duration as StdDuration,
};
use tokio::time::interval;

// -----------------------------------------------------------------------------
// CONSTANTS & CRYPTOGRAPHIC ENGINES
// -----------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn git_sha1(data: &[u8]) -> String {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;
    let mut padded = data.to_vec();
    let bit_len = (padded.len() as u64) * 8;
    padded.push(0x80);
    while (padded.len() * 8) % 512 != 448 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    format!("{:08x}{:08x}{:08x}{:08x}{:08x}", h0, h1, h2, h3, h4)
}

fn sha256(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let mut padded = data.to_vec();
    let bit_len = (padded.len() as u64) * 8;
    padded.push(0x80);
    while (padded.len() * 8) % 512 != 448 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h_val] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h = [
            h[0].wrapping_add(a),
            h[1].wrapping_add(b),
            h[2].wrapping_add(c),
            h[3].wrapping_add(d),
            h[4].wrapping_add(e),
            h[5].wrapping_add(f),
            h[6].wrapping_add(g),
            h[7].wrapping_add(h_val),
        ];
    }
    h.iter().map(|x| format!("{:08x}", x)).collect()
}

// -----------------------------------------------------------------------------
// POOL & STATE MACHINE STRUCTURES
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct BlockTemplate {
    pub version: u32,
    pub prev_block: String,
    pub merkle_root: String,
    pub pool_target: String,
}

pub struct DecentralizedPoolNode {
    pub miner_id: String,
    pub current_template: Arc<Mutex<BlockTemplate>>,
    pub shares_submitted: u64,
}

impl DecentralizedPoolNode {
    pub fn new(miner_id: &str, initial_template: BlockTemplate) -> Self {
        Self {
            miner_id: miner_id.to_string(),
            current_template: Arc::new(Mutex::new(initial_template)),
            shares_submitted: 0,
        }
    }

    pub fn verify_incoming_share(&mut self, nonce: u64) -> bool {
        let template = self.current_template.lock().unwrap();
        let payload = format!("{}{}{}{}", template.version, template.prev_block, template.merkle_root, nonce);
        let intermediate_hash = sha256(payload.as_bytes());
        let final_hash = sha256(intermediate_hash.as_bytes());

        if final_hash.starts_with(&template.pool_target) {
            self.shares_submitted += 1;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum SyncStage {
    Hour,
    Minute,
    Second,
    NonceGrind1Bit,
    NonceGrind2Bit,
}

pub struct SyncNode {
    pub id: usize,
    pub adjustment: Duration,
    pub stage: SyncStage,
    pub start_nonce: u64,
    pub nonce: u64,
    pub success: bool,
    pub last_hash: String,
}

impl SyncNode {
    pub fn new(id: usize, offset_sec: i64, total_nodes: usize) -> Self {
        let stride = u64::MAX / (total_nodes as u64);
        let start_nonce = (id as u64) * stride;
        Self {
            id,
            adjustment: Duration::seconds(offset_sec),
            stage: SyncStage::Hour,
            start_nonce,
            nonce: start_nonce,
            success: false,
            last_hash: String::from("0000000000000000000000000000000000000000"),
        }
    }

    pub fn get_logical_utc(&self) -> DateTime<Utc> {
        Utc::now() + self.adjustment
    }

    pub fn update_stage(&mut self, spread: i64, all_same_minute: bool, global_1bit_reached: bool) {
        match self.stage {
            SyncStage::Hour => {
                if spread < 3600 {
                    self.stage = SyncStage::Minute;
                }
            }
            SyncStage::Minute => {
                if spread < 60 {
                    self.stage = SyncStage::Second;
                }
            }
            SyncStage::Second => {
                if spread == 0 && all_same_minute {
                    self.stage = SyncStage::NonceGrind1Bit;
                }
            }
            SyncStage::NonceGrind1Bit => {
                if spread > 0 || !all_same_minute {
                    self.stage = SyncStage::Second;
                    self.success = false;
                    self.nonce = self.start_nonce;
                } else if global_1bit_reached {
                    self.stage = SyncStage::NonceGrind2Bit;
                    self.success = false;
                }
            }
            SyncStage::NonceGrind2Bit => {
                if spread > 0 || !all_same_minute {
                    self.stage = SyncStage::Second;
                    self.success = false;
                    self.nonce = self.start_nonce;
                }
            }
        }
    }

    pub fn grind_nonce(&mut self, target: &str, template: &BlockTemplate) {
        let time = self.get_logical_utc();
        let minute = time.minute();
        loop {
            let input = format!("BLOCK-{}-{}-{}-{}", template.prev_block, template.merkle_root, minute, self.nonce);
            let hash = if target == "00" {
                let round1 = sha256(input.as_bytes());
                sha256(round1.as_bytes())
            } else {
                git_sha1(input.as_bytes())
            };

            if target == "00" {
                if hash.starts_with("00") {
                    self.last_hash = hash;
                    self.success = true;
                    break;
                } else if hash.starts_with("0") {
                    self.last_hash = hash;
                    self.nonce += 1;
                    break;
                }
            } else {
                self.last_hash = hash;
                if self.last_hash.starts_with(target) {
                    self.success = true;
                } else {
                    self.nonce += 1;
                }
                break;
            }
            self.nonce += 1;
        }
    }
}

fn get_median_diff(timestamps: &[i64], current: i64) -> i64 {
    let mut diffs: Vec<i64> = timestamps.iter().map(|t| t - current).collect();
    diffs.sort();
    diffs[diffs.len() / 2]
}

// -----------------------------------------------------------------------------
// P2P DATA MODELS & NETWORK BEHAVIOUR
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmapEntry {
    pub ip_prefix: String,
    pub asn: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmapPayload {
    pub epoch: u64,
    pub sender_id: String,
    pub solved_nonce: u64,
    pub entries: Vec<AsmapEntry>,
}

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub struct QuorumAggregator {
    threshold: usize,
    votes: HashMap<(String, u32), usize>,
    received_peers: HashMap<String, bool>,
}

impl QuorumAggregator {
    pub fn new(threshold: usize) -> Self {
        Self {
            threshold,
            votes: HashMap::new(),
            received_peers: HashMap::new(),
        }
    }

    pub fn process_payload(&mut self, payload: AsmapPayload) -> bool {
        if self.received_peers.contains_key(&payload.sender_id) {
            return false;
        }
        self.received_peers.insert(payload.sender_id, true);

        for entry in payload.entries {
            *self.votes.entry((entry.ip_prefix, entry.asn)).or_insert(0) += 1;
        }

        self.received_peers.len() >= self.threshold
    }

    pub fn finalize_asmap(&self) -> HashMap<String, u32> {
        let mut consensus_map = HashMap::new();
        for ((prefix, asn), count) in &self.votes {
            if *count >= self.threshold {
                consensus_map.insert(prefix.clone(), *asn);
            }
        }
        consensus_map
    }
}

pub fn export_bitcoin_core_asmap(consensus_map: &HashMap<String, u32>, file_path: &str) -> Result<()> {
    let mut raw_bytes = Vec::new();
    raw_bytes.extend_from_slice(b"ASMAP_QUORUM_V1\n");

    for (prefix, asn) in consensus_map {
        let entry_str = format!("{} {}\n", prefix, asn);
        raw_bytes.extend_from_slice(entry_str.as_bytes());
    }

    let mut file = File::create(file_path)
        .with_context(|| format!("Failed to create output ASMap file at {}", file_path))?;
    file.write_all(&raw_bytes)?;
    println!("[+] Successfully written Bitcoin Core ASMap file: {}", file_path);
    Ok(())
}

// -----------------------------------------------------------------------------
// MAIN RUNTIME & LIBP2P LOOPS
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("[*] Initializing ASMap Quorum Node with Proof-of-Work Sync Engine...");

    let total_nodes = 10;
    let initial_job = BlockTemplate {
        version: 4,
        prev_block: "000000000000000000021c33f24bf7aef12d".to_string(),
        merkle_root: "94b8e19c20cb3ffbb123a".to_string(),
        pool_target: "00".to_string(),
    };

    let mut pool_node = DecentralizedPoolNode::new("pleb_pool_partitioner", initial_job);
    let mut sync_nodes: Vec<SyncNode> = (0..total_nodes)
        .map(|i| {
            let offset = match i {
                0..=2 => 10,
                3..=5 => 5,
                _ => 2,
            };
            SyncNode::new(i, offset, total_nodes)
        })
        .collect();

    // Setup libp2p Swarm
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::seconds(1).to_std().unwrap())
                .build()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                key.public().to_peer_id(),
            )?;

            Ok(AppBehaviour { gossipsub, mdns })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(StdDuration::from_secs(60)))
        .build();

    let topic = gossipsub::IdentTopic::new("bitcoin-asmap-quorum");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut aggregator = QuorumAggregator::new(3);
    let mut sync_timer = interval(StdDuration::from_millis(50));
    let peer_id_str = swarm.local_peer_id().to_string();
    let mut round = 1;

    loop {
        tokio::select! {
            _ = sync_timer.tick() => {
                let current_times: Vec<DateTime<Utc>> = sync_nodes.iter().map(|n| n.get_logical_utc()).collect();
                let timestamps: Vec<i64> = current_times.iter().map(|t| t.timestamp()).collect();
                let spread = (timestamps.iter().max().unwrap() - timestamps.iter().min().unwrap()).abs();
                let all_same_minute = current_times.iter().all(|t| t.minute() == current_times[0].minute());
                let global_1bit_reached = sync_nodes.iter().all(|n| n.stage == SyncStage::NonceGrind1Bit && n.success);

                let has_consensus = {
                    let active_template = pool_node.current_template.lock().unwrap();

                    for i in 0..total_nodes {
                        sync_nodes[i].update_stage(spread, all_same_minute, global_1bit_reached);
                        match sync_nodes[i].stage {
                            SyncStage::Hour | SyncStage::Minute | SyncStage::Second => {
                                let d = get_median_diff(&timestamps, timestamps[i]);
                                let step = if sync_nodes[i].stage == SyncStage::Second { d.signum() } else { d / 2 };
                                sync_nodes[i].adjustment = sync_nodes[i].adjustment + Duration::seconds(step);
                            },
                            SyncStage::NonceGrind1Bit => {
                                if !sync_nodes[i].success {
                                    sync_nodes[i].grind_nonce("0", &active_template);
                                }
                            },
                            SyncStage::NonceGrind2Bit => {
                                if !sync_nodes[i].success {
                                    sync_nodes[i].grind_nonce("00", &active_template);
                                }
                            }
                        };
                    }
                    sync_nodes.iter().all(|n| n.stage == SyncStage::NonceGrind2Bit && n.success)
                };

                if has_consensus {
                    println!("\n[!] Quorum Proof Consensus Achieved at Round {}. Submitting shares...", round);
                    for i in 0..total_nodes {
                        pool_node.verify_incoming_share(sync_nodes[i].nonce);
                    }

                    let payload = AsmapPayload {
                        epoch: 1,
                        sender_id: peer_id_str.clone(),
                        solved_nonce: sync_nodes[0].nonce,
                        entries: vec![
                            AsmapEntry { ip_prefix: "1.0.0.0/24".into(), asn: 13335 },
                            AsmapEntry { ip_prefix: "8.8.8.0/24".into(), asn: 15169 },
                        ],
                    };

                    if let Ok(encoded) = serde_json::to_vec(&payload) {
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), encoded);
                        println!("[>] Broadcasted verified ASMap payload to libp2p network.");
                    }
                }
                round += 1;
            }

            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("[+] Discovered peer via mDNS: {}", peer_id);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                    if let Ok(payload) = serde_json::from_slice::<AsmapPayload>(&message.data) {
                        println!("[<] Received ASMap payload from peer: {}", payload.sender_id);
                        if aggregator.process_payload(payload) {
                            println!("[!] Quorum threshold reached! Finalizing Bitcoin Core ASMap...");
                            let consensus_data = aggregator.finalize_asmap();
                            let _ = export_bitcoin_core_asmap(&consensus_data, "asmap.map");
                            let _ = export_bitcoin_core_asmap(&consensus_data, "final_result.txt");
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

// -----------------------------------------------------------------------------
// TESTING SUITE
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_golden_vector() {
        assert_eq!(git_sha1(b"hello world"), "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
    }

    #[test]
    fn test_sha256_golden_vector() {
        assert_eq!(
            sha256(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

type ASNEntry = (Vec<bool>, u32);
type ASNDiff = (Vec<bool>, u32, u32);

fn bit_length_u32(v: u32) -> u32 {
    32 - v.leading_zeros()
}

fn parse_network_prefix(input: &str) -> Result<(IpAddr, u8)> {
    let (addr, prefix) = input
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid network '{input}'"))?;
    let ip: IpAddr = addr.parse().with_context(|| format!("invalid network '{input}'"))?;
    let prefix_len: u8 = prefix
        .parse()
        .with_context(|| format!("invalid network '{input}'"))?;
    match ip {
        IpAddr::V4(_) if prefix_len <= 32 => Ok((ip, prefix_len)),
        IpAddr::V6(_) if prefix_len <= 128 => Ok((ip, prefix_len)),
        IpAddr::V4(_) | IpAddr::V6(_) => bail!("invalid network '{input}'"),
    }
}

fn ip_to_bits(ip: IpAddr, prefix_len: u8) -> Vec<bool> {
    let (netrange, num_bits) = match ip {
        IpAddr::V4(v4) => ((u32::from(v4) as u128) + 0xffff_0000_0000u128, prefix_len as usize + 96),
        IpAddr::V6(v6) => (u128::from_be_bytes(v6.octets()), prefix_len as usize),
    };
    (0..num_bits)
        .map(|i| ((netrange >> (127 - i)) & 1) != 0)
        .collect()
}

fn bits_to_network(prefix: &[bool]) -> Result<String> {
    let netrange = prefix
        .iter()
        .enumerate()
        .fold(0u128, |acc, (i, bit)| if *bit { acc | (1u128 << (127 - i)) } else { acc });
    if prefix.len() >= 96 && (netrange >> 32) == 0xffff {
        let addr = Ipv4Addr::from((netrange & 0xffff_ffff) as u32);
        return Ok(format!("{addr}/{}", prefix.len() - 96));
    }
    Ok(format!("{}/{}", Ipv6Addr::from(netrange), prefix.len()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

    fn split_if_leaf(&mut self) {
        if let TrieNode::Leaf(value) = *self {
            *self = TrieNode::Branch(Box::new(TrieNode::Leaf(value)), Box::new(TrieNode::Leaf(value)));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
            node.split_if_leaf();
            match node {
                TrieNode::Leaf(_) => unreachable!(),
                TrieNode::Branch(left, right) => {
                    recurse(if prefix[offset] { right } else { left }, prefix, asn, offset + 1);
                    if let TrieNode::Branch(l, r) = node {
                        if let (TrieNode::Leaf(a), TrieNode::Leaf(b)) = (&**l, &**r) {
                            if a == b {
                                *node = TrieNode::leaf(*a);
                            }
                        }
                    }
                }
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
                TrieNode::Branch(left, right) => {
                    node = if *bit { right } else { left };
                }
            }
        }
        match node {
            TrieNode::Leaf(v) => Some(*v),
            TrieNode::Branch(_, _) => None,
        }
    }

    pub fn extends(&self, req: &ASMap) -> bool {
        fn recurse(actual: &TrieNode, require: &TrieNode) -> bool {
            match require {
                TrieNode::Leaf(0) => true,
                TrieNode::Leaf(reqv) => match actual {
                    TrieNode::Leaf(av) => av == reqv,
                    TrieNode::Branch(left, right) => recurse(left, require) && recurse(right, require),
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
                    if fill {
                        if let (TrieNode::Leaf(a), TrieNode::Leaf(b)) = (&**left, &**right) {
                            if a == b && *a > 0 {
                                out.push((prefix.clone(), *a));
                                return;
                            }
                        }
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
                    let mut map = HashMap::new();
                    map.insert(if fill { None } else { Some(0) }, BinNode::end());
                    (map, true)
                }
                TrieNode::Leaf(v) => {
                    let mut map = HashMap::new();
                    map.insert(None, BinNode::leaf(*v));
                    map.insert(Some(*v), BinNode::end());
                    (map, false)
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

                    let mut candidate = |ctx: Option<u32>, a: Option<&BinNode>, b: Option<&BinNode>, f: fn(BinNode, BinNode) -> BinNode| {
                        if let (Some(a), Some(b)) = (a, b) {
                            let cand = f(a.clone(), b.clone());
                            let should_replace = ret.get(&ctx).map(|old| cand.size < old.size).unwrap_or(true);
                            if should_replace {
                                ret.insert(ctx, cand);
                            }
                        }
                    };

                    for ctx in union {
                        candidate(ctx, left_map.get(&ctx), right_map.get(&ctx), BinNode::branch);
                        candidate(ctx, left_map.get(&None), right_map.get(&ctx), BinNode::branch);
                        candidate(ctx, left_map.get(&ctx), right_map.get(&None), BinNode::branch);
                    }
                    if !hole {
                        let keys: Vec<Option<u32>> = ret.keys().copied().filter(|k| k.is_some()).collect();
                        for ctx in keys {
                            if let Some(node) = ret.get(&ctx).cloned() {
                                let defaulted = BinNode::default(ctx.unwrap(), node);
                                let should_replace = ret
                                    .get(&None)
                                    .map(|old| defaulted.size < old.size)
                                    .unwrap_or(true);
                                if should_replace {
                                    ret.insert(None, defaulted);
                                }
                            }
                        }
                    }
                    if let Some(best_default) = ret.get(&None) {
                        ret.retain(|ctx, enc| *ctx == None || enc.size < best_default.size);
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
        fn encode_bits(node: &BinNode, bits: &mut Vec<u8>) {
            _CODER_INS.encode(node.ins_value(), bits);
            match &node.kind {
                BinNodeKind::Return(v) => _CODER_ASN.encode(*v, bits),
                BinNodeKind::Jump(left, right) => {
                    _CODER_JUMP.encode(left.size as u32, bits);
                    encode_bits(left, bits);
                    encode_bits(right, bits);
                }
                BinNodeKind::Match(v, sub) => {
                    _CODER_MATCH.encode(*v, bits);
                    encode_bits(sub, bits);
                }
                BinNodeKind::Default(v, sub) => {
                    _CODER_ASN.encode(*v, bits);
                    encode_bits(sub, bits);
                }
                BinNodeKind::End => {}
            }
        }

        let binnode = self.to_binnode(fill);
        let mut bits = Vec::new();
        if !matches!(binnode.kind, BinNodeKind::End) {
            encode_bits(&binnode, &mut bits);
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
        if nbits > 0 {
            bytes.push(val);
        }
        bytes
    }

    pub fn from_binary(bindata: &[u8]) -> Option<Self> {
        let mut bits = Vec::new();
        for byte in bindata {
            for i in 0..8 {
                bits.push((byte >> i) & 1);
            }
        }

        fn recurse(bits: &[u8], bitpos: usize) -> Option<(BinNode, usize)> {
            let (insval, mut bitpos) = _CODER_INS.decode(bits, bitpos)?;
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
            return Some(Self::default());
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
                BinNodeKind::Jump(left, right) => Some(TrieNode::branch(recurse(*left, default)?, recurse(*right, default)?)),
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
        let mut i = 0;
        let mut total = 0u32;
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
            if let BinNodeKind::Match(v, sub) = right.kind.clone() {
                if v <= 0xff {
                    return Self::match_node(v + (1 << bit_length_u32(v)), *sub);
                }
            }
            return Self::match_node(3, right);
        }
        if matches!(right.kind, BinNodeKind::End) {
            if let BinNodeKind::Match(v, sub) = left.kind.clone() {
                if v <= 0xff {
                    return Self::match_node(v + (1 << (bit_length_u32(v) - 1)), *sub);
                }
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
        if matches!(sub.kind, BinNodeKind::Return(_) | BinNodeKind::Default(_, _)) {
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
const _CODER_JUMP: VarLenCoder = VarLenCoder::new(17, &[5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]);

#[derive(Deserialize)]
struct AddrInfo {
    address: String,
    network: String,
}

fn open_input(path: Option<&str>) -> Result<Box<dyn Read>> {
    match path {
        Some("-") | None => Ok(Box::new(io::stdin())),
        Some(path) => Ok(Box::new(File::open(path).with_context(|| format!("Input file '{path}' cannot be read"))?)),
    }
}

fn open_output(path: Option<&str>, binary: bool) -> Result<Box<dyn Write>> {
    match path {
        Some("-") | None => {
            if binary && io::stdout().is_terminal() {
                bail!("Not much use in writing binary to a TTY. Please specify an output file or pipe output to another process.");
            }
            Ok(Box::new(io::stdout()))
        }
        Some(path) => Ok(Box::new(File::create(path).with_context(|| format!("Output file '{path}' cannot be written to"))?)),
    }
}

fn load_file(mut input: Box<dyn Read>, input_name: &str) -> Result<ASMap> {
    let mut contents = Vec::new();
    input.read_to_end(&mut contents).with_context(|| format!("Input file '{input_name}' cannot be read"))?;

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
                parsed = Vec::new();
                break;
            }
            let asn = asn.unwrap();
            if !asn.starts_with("AS") || asn.len() <= 2 || !asn[2..].chars().all(|c| c.is_ascii_digit()) {
                txt_error = Some(format!("invalid ASN '{asn}'"));
                parsed = Vec::new();
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

fn save_binary(mut output: Box<dyn Write>, state: &ASMap, fill: bool, output_name: &str) -> Result<()> {
    let contents = state.to_binary(fill);
    output.write_all(&contents).with_context(|| format!("Output file '{output_name}' cannot be written to"))?;
    Ok(())
}

fn save_text(mut output: Box<dyn Write>, state: &ASMap, fill: bool, overlapping: bool, output_name: &str) -> Result<()> {
    for (prefix, asn) in state.to_entries(fill, overlapping) {
        let net = bits_to_network(&prefix)?;
        writeln!(output, "{net} AS{asn}").with_context(|| format!("Output file '{output_name}' cannot be written to"))?;
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
    let infile = pos.get(0).map(String::as_str);
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
    let infile = pos.get(0).map(String::as_str);
    let outfile = pos.get(1).map(String::as_str);
    let input_name = infile.unwrap_or("<stdin>");
    let output_name = outfile.unwrap_or("<stdout>");
    let state = load_file(open_input(infile)?, input_name)?;
    save_text(open_output(outfile, false)?, &state, fill, overlapping, output_name)
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
        let net = bits_to_network(&prefix)?;
        if net.contains('.') {
            ipv4_changed += 1u128 << (32 - net.split('/').last().unwrap().parse::<u32>()?);
            ipv4_entries_changed += 1;
        } else {
            ipv6_changed += 1u128 << (128 - net.split('/').last().unwrap().parse::<u32>()?);
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
        "# Summary\nIPv4: {} entries with {}{} addresses changed\nIPv6: {} entries with {}{} addresses changed",
        ipv4_entries_changed, ipv4_changed, ipv4_change_str, ipv6_entries_changed, ipv6_changed, ipv6_change_str
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
    let addrs_file = File::open(&pos[2]).with_context(|| format!("Input file '{}' cannot be read", &pos[2]))?;
    let address_info: Vec<AddrInfo> = serde_json::from_reader(addrs_file)?;
    let addrs: Vec<String> = address_info
        .into_iter()
        .filter(|a| a.network == "ipv4" || a.network == "ipv6")
        .map(|a| a.address)
        .collect();

    let mut reassignments: HashMap<(u32, u32), Vec<String>> = HashMap::new();
    for addr in &addrs {
        let ip: IpAddr = addr.parse().with_context(|| format!("invalid address '{addr}'"))?;
        let prefix = match ip {
            IpAddr::V4(v4) => ip_to_bits(IpAddr::V4(v4), 32),
            IpAddr::V6(v6) => ip_to_bits(IpAddr::V6(v6), 128),
        };
        let old_asn = state1.lookup(&prefix).unwrap_or(0);
        let new_asn = state2.lookup(&prefix).unwrap_or(0);
        if new_asn != old_asn {
            reassignments.entry((old_asn, new_asn)).or_default().push(addr.clone());
        }
    }
    let mut reassignments: Vec<_> = reassignments.into_iter().collect();
    reassignments.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    let mut num_reassignment_type = HashMap::<(bool, bool), usize>::new();
    for ((old_asn, new_asn), reassigned_addrs) in &reassignments {
        let num_reassigned = reassigned_addrs.len();
        *num_reassignment_type.entry(((*old_asn != 0), (*new_asn != 0))).or_insert(0) += num_reassigned;
        let old_asn_str = if *old_asn == 0 { "unassigned".to_string() } else { format!("AS{old_asn}") };
        let new_asn_str = if *new_asn == 0 { "unassigned".to_string() } else { format!("AS{new_asn}") };
        let opt = if show_addresses {
            format!(": {}", reassigned_addrs.join(", "))
        } else {
            String::new()
        };
        println!("{num_reassigned} address(es) reassigned from {old_asn_str} to {new_asn_str}{opt}");
    }
    let num_reassignments: usize = reassignments.iter().map(|(_, addrs)| addrs.len()).sum();
    let share = if addrs.is_empty() { 0.0 } else { num_reassignments as f64 / addrs.len() as f64 };
    println!(
        "Summary: {num_reassignments:,} ({:.2}%) of {:,} addresses were reassigned (migrations={}, assignments={}, unassignments={})",
        share * 100.0,
        addrs.len(),
        num_reassignment_type.get(&(true, true)).copied().unwrap_or(0),
        num_reassignment_type.get(&(false, true)).copied().unwrap_or(0),
        num_reassignment_type.get(&(true, false)).copied().unwrap_or(0),
    );
    Ok(())
}

fn usage() {
    eprintln!(
        "Usage:\n  asmap encode [-f|--fill] [infile] [outfile]\n  asmap decode [-f|--fill] [-n|--nonoverlapping] [infile] [outfile]\n  asmap diff [-i|--ignore-unassigned] infile1 infile2\n  asmap diff_addrs [-s|--show-addresses] infile1 infile2 addrs_file"
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
        _ => {
            usage();
            bail!("unknown subcommand '{cmd}'")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_roundtrip_ipv4() {
        let bits = ip_to_bits("1.2.3.0".parse::<IpAddr>().unwrap(), 24);
        assert_eq!(bits_to_network(&bits).unwrap(), "1.2.3.0/24");
    }

    #[test]
    fn network_roundtrip_ipv6() {
        let bits = ip_to_bits("2001:db8::".parse::<IpAddr>().unwrap(), 32);
        assert_eq!(bits_to_network(&bits).unwrap(), "2001:db8::/32");
    }

    #[test]
    fn binary_roundtrip_empty() {
        let state = ASMap::new();
        let enc = state.to_binary(false);
        let dec = ASMap::from_binary(&enc).unwrap();
        assert_eq!(state, dec);
    }
}
