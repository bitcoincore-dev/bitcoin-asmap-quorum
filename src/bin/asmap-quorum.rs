use anyhow::{Context, Result};
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns,
    swarm::{NetworkBehaviour, SwarmEvent},
    PeerId, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::Write,
    str::FromStr,
    time::Duration,
};
use tokio::time::interval;

// -----------------------------------------------------------------------------
// Data Models & Network Behaviour
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
    pub entries: Vec<AsmapEntry>,
}

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

// -----------------------------------------------------------------------------
// Quorum Aggregator Engine
// -----------------------------------------------------------------------------

pub struct QuorumAggregator {
    threshold: usize,
    // (ip_prefix, asn) -> count of peers supporting this mapping
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
            return false; // Prevent double-voting from same peer in single epoch
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

// -----------------------------------------------------------------------------
// Bitcoin Core ASMap Binary Encoder Stub
// -----------------------------------------------------------------------------

pub fn export_bitcoin_core_asmap(
    consensus_map: &HashMap<String, u32>,
    file_path: &str,
) -> Result<()> {
    // Bitcoin Core ASMap utilizes a compact bit-stream encoding for IP tries.
    // Raw binary encoding logic transforms prefix trees into structural byte vectors.
    let mut raw_bytes = Vec::new();
    
    // Header metadata marker for custom ASMap binaries
    raw_bytes.extend_from_slice(b"ASMAP_QUORUM_V1");

    for (prefix, asn) in consensus_map {
        let entry_str = format!("{}:{}\n", prefix, asn);
        raw_bytes.extend_from_slice(entry_str.as_bytes());
    }

    let mut file = File::create(file_path)
        .with_context(|| format!("Failed to create output ASMap file at {}", file_path))?;
    file.write_all(&raw_bytes)?;
    println!("[+] Generated Bitcoin Core ASMap file: {}", file_path);
    Ok(())
}

// -----------------------------------------------------------------------------
// Main Event Loop
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("[*] Starting ASMap Quorum Node...");

    // Build libp2p Swarm with TCP, Noise encryption, and Yamux multiplexing
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
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
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Subscribe to ASMap Gossip Topic
    let topic = gossipsub::IdentTopic::new("bitcoin-asmap-quorum");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut aggregator = QuorumAggregator::new(3); // Quorum threshold = 3 peers
    let mut broadcast_timer = interval(Duration::from_secs(10));
    let peer_id_str = swarm.local_peer_id().to_string();

    loop {
        tokio::select! {
            _ = broadcast_timer.tick() => {
                // Periodically publish local ASMap observations
                let mock_payload = AsmapPayload {
                    epoch: 1,
                    sender_id: peer_id_str.clone(),
                    entries: vec![
                        AsmapEntry { ip_prefix: "1.0.0.0/24".into(), asn: 13335 },
                        AsmapEntry { ip_prefix: "8.8.8.0/24".into(), asn: 15169 },
                    ],
                };

                if let Ok(encoded) = serde_json::to_vec(&mock_payload) {
                    let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), encoded);
                    println!("[>] Broadcasted local ASMap assertion to network.");
                }
            }

            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("[+] Discovered peer via mDNS: {}", peer_id);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    message,
                    ..
                })) => {
                    if let Ok(payload) = serde_json::from_slice::<AsmapPayload>(&message.data) {
                        println!("[<] Received ASMap payload from peer: {}", payload.sender_id);
                        
                        let quorum_reached = aggregator.process_payload(payload);
                        if quorum_reached {
                            println!("[!] Quorum threshold reached. Processing consensus ASMap...");
                            let consensus_data = aggregator.finalize_asmap();
                            let _ = export_bitcoin_core_asmap(&consensus_data, "asmap.map");
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
