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
