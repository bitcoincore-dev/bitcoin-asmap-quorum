//! Core library for ASMap parsing, quorum claim processing, and CLI orchestration.
//!
//! The crate exposes the [`run`] entrypoint used by both binaries and keeps the
//! ASMap/domain types in one place so encode/decode, diffing, and quorum modes
//! share identical logic.

use anyhow::{Context, Result, anyhow, bail};
use asmap_codec::{
    bits_to_network, ip_to_bits, load_file, network_address_count, save_binary, save_text,
};
use futures::StreamExt;
use libp2p::{
    PeerId, SwarmBuilder,
    core::multiaddr::{Multiaddr, Protocol},
    dcutr, gossipsub, identify, mdns, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use log::{debug, info, trace, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;
use tokio::time::interval;

#[cfg(feature = "nostr")]
use nostr::prelude::*;
#[cfg(feature = "nostr")]
use nostr_sdk::prelude::{AckPolicy, Client};

/// Re-export of the codec crate's ASMap so downstream users of this crate keep
/// a single canonical type (it is a public field of [`ConsensusArtifact`]).
pub use asmap_codec::ASMap;

pub const IPFS_BOOTSTRAP_NODES: [&str; 4] = [
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

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

fn assigned_collectors(
    collectors: &[u32],
    local_peer_id: &str,
    peers: &HashSet<String>,
) -> Vec<u32> {
    let mut participants = peers.iter().cloned().collect::<Vec<_>>();
    participants.push(local_peer_id.to_string());
    participants.sort();
    participants.dedup();
    if participants.is_empty() {
        return collectors.to_vec();
    }
    let local_index = participants
        .iter()
        .position(|peer| peer == local_peer_id)
        .unwrap_or(0);
    collectors
        .iter()
        .enumerate()
        .filter_map(|(idx, collector)| {
            if idx % participants.len() == local_index {
                Some(*collector)
            } else {
                None
            }
        })
        .collect()
}

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

fn save_json_report(path: &Path, artifact: &ConsensusArtifact) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Output file '{}' cannot be written to", path.display()))?;
    let report = ConsensusReport::from(artifact);
    serde_json::to_writer_pretty(file, &report)?;
    #[cfg(feature = "nostr")]
    {
        _save_nostr_bundle(path, artifact)?;
    }
    Ok(())
}

#[cfg(feature = "nostr")]
fn nostr_sidecar_path(report_path: &Path) -> PathBuf {
    let mut path = report_path.to_path_buf();
    path.set_extension("nostr.json");
    path
}

#[cfg(feature = "nostr")]
fn hash_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(feature = "nostr")]
fn map_hash_hex(map: &ASMap) -> String {
    hash_hex(&map.to_binary(false))
}

#[cfg(feature = "nostr")]
fn deterministic_nostr_keys(seed: usize) -> Result<Keys> {
    Keys::parse(&format!("{seed:064x}")).context("invalid deterministic nostr secret key")
}

#[cfg(feature = "nostr")]
static NOSTR_RELAY_URLS_OVERRIDE: std::sync::OnceLock<std::sync::Mutex<Option<Vec<String>>>> =
    std::sync::OnceLock::new();

#[cfg(feature = "nostr")]
const DEFAULT_NOSTR_RELAYS: [&str; 6] = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.snort.social",
    "wss://relay.primal.net",
    "wss://relay.nostr.band",
    "wss://offchain.pub",
];

#[cfg(feature = "nostr")]
fn nostr_relay_urls_override() -> Option<Vec<String>> {
    NOSTR_RELAY_URLS_OVERRIDE
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

#[cfg(feature = "nostr")]
fn nostr_relay_urls() -> Vec<String> {
    if let Some(relays) = nostr_relay_urls_override() {
        return relays;
    }

    match std::env::var("ASMAP_NOSTR_RELAYS") {
        Ok(value) => value
            .split(',')
            .map(str::trim)
            .filter(|relay| !relay.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Err(_) => DEFAULT_NOSTR_RELAYS
            .iter()
            .map(|relay| (*relay).to_owned())
            .collect(),
    }
}

#[cfg(feature = "nostr")]
fn publish_nostr_bundle(bundle: &NostrQuorumBundle) -> Result<()> {
    let relays = nostr_relay_urls();
    if relays.is_empty() {
        bail!("no nostr relays configured");
    }

    let bundle = bundle.clone();
    std::thread::spawn(move || -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create nostr publish runtime")?;

        runtime.block_on(async move {
            let client: Client = Client::builder().build();

            for relay in &relays {
                println!("[nostr] broadcasting to relay: {relay}");
                client.add_relay(relay).and_connect().await?;
            }

            let announcement_output = client
                .send_event(&bundle.announcement)
                .to(relays.iter().map(String::as_str))
                .ack_policy(AckPolicy::none())
                .await?;
            if announcement_output.success.len() != relays.len() {
                bail!(
                    "nostr announcement was acknowledged by {} of {} relays",
                    announcement_output.success.len(),
                    relays.len()
                );
            }

            for event in &bundle.attestations {
                let output = client
                    .send_event(event)
                    .to(relays.iter().map(String::as_str))
                    .ack_policy(AckPolicy::none())
                    .await?;
                if output.success.len() != relays.len() {
                    bail!(
                        "nostr attestation was acknowledged by {} of {} relays",
                        output.success.len(),
                        relays.len()
                    );
                }
            }

            Ok(())
        })
    })
    .join()
    .map_err(|_| anyhow!("nostr publish thread panicked"))??;

    Ok(())
}

#[cfg(feature = "nostr")]
fn _save_nostr_bundle(report_path: &Path, artifact: &ConsensusArtifact) -> Result<()> {
    let sidecar = nostr_sidecar_path(report_path);
    let file = File::create(&sidecar)
        .with_context(|| format!("Output file '{}' cannot be written to", sidecar.display()))?;
    let result_hash = map_hash_hex(&artifact.map);
    let coordinator_keys = deterministic_nostr_keys(1)?;
    let repository = Coordinate::new(Kind::GitRepoAnnouncement, coordinator_keys.public_key())
        .identifier("bitcoin-asmap-quorum");
    let announcement = GitIssue {
        repository,
        content: format!(
            "Quorum reached for epoch {}.\n\n- topic: {}\n- threshold: {}\n- accepted claims: {}\n- result hash: `{}`\n- map hash: `{}`",
            artifact.epoch,
            artifact.topic,
            artifact.threshold,
            artifact.accepted_claims,
            result_hash,
            result_hash,
        ),
        subject: Some(format!("Quorum reached for epoch {}", artifact.epoch)),
        labels: vec![
            String::from("quorum"),
            String::from("announcement"),
            format!("epoch-{}", artifact.epoch),
        ],
    }
    .finalize(&coordinator_keys)?;
    let announcement_id = announcement.id;
    let announcement_kind = announcement.kind;
    let announcement_pubkey = announcement.pubkey;

    let attestations = artifact
        .participants
        .iter()
        .enumerate()
        .map(|(idx, relay_id)| {
            let relay_keys = deterministic_nostr_keys(idx + 2)?;
            let content = format!(
                "Attestation from relay `{}` for announcement `{}`.\n\n- result hash: `{}`\n- map hash: `{}`\n- accepted claims: {}",
                relay_id,
                announcement_id,
                result_hash,
                result_hash,
                artifact.accepted_claims
            );
            let target =
                CommentTarget::event(announcement_id, announcement_kind, Some(announcement_pubkey), None);
            CommentBuilder::new(content, target.clone())
                .root(target)
                .finalize(&relay_keys)
                .map_err(anyhow::Error::from)
        })
        .collect::<Result<Vec<_>>>()?;

    let bundle = NostrQuorumBundle {
        announcement,
        attestations,
    };
    println!("[nostr] announcement id: {}", bundle.announcement.id);
    for event in &bundle.attestations {
        println!("[nostr] attestation id: {}", event.id);
    }
    publish_nostr_bundle(&bundle)?;
    serde_json::to_writer_pretty(file, &bundle)?;
    Ok(())
}

#[cfg(not(feature = "nostr"))]
fn _save_nostr_bundle(_report_path: &Path, _artifact: &ConsensusArtifact) -> Result<()> {
    Ok(())
}

fn load_json_report(path: &str) -> Result<ConsensusArtifact> {
    let file = File::open(path).with_context(|| format!("Input file '{path}' cannot be read"))?;
    let report: ConsensusReport = serde_json::from_reader(file)?;
    report.try_into()
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

/// Normalizes a consensus prefix string, masking host bits instead of rejecting.
///
/// The codec's [`asmap_codec::parse_network_prefix`] is strict, matching `net_to_prefix` in
/// `contrib/asmap/asmap.py`: `1.2.3.4/8` is an error there, not `1.0.0.0/8`.
/// That is right for text ASMap files, but the consensus layer also handles
/// prefixes it did not author — peer-supplied claim entries and reports written
/// by v0.0.8, which masked host bits silently inside `ip_to_bits`. Masking here
/// keeps every artifact v0.0.8 could emit loadable, and — because both the
/// write path ([`QuorumEngine::finalize`]) and the read paths (`verify_report`,
/// `TryFrom<ConsensusReport> for ConsensusArtifact`) go through this one
/// function — guarantees the tool can always verify a report it just wrote.
///
/// Returns the canonical text form alongside the parsed address and length.
fn canonical_consensus_prefix(input: &str) -> Result<(String, IpAddr, u8)> {
    let invalid = || anyhow!("invalid network '{input}'");
    let (addr, len) = input.split_once('/').ok_or_else(invalid)?;
    let ip: IpAddr = addr.parse().map_err(|_| invalid())?;
    let prefix_len: u8 = len.parse().map_err(|_| invalid())?;
    let width: u8 = if ip.is_ipv4() { 32 } else { 128 };
    if prefix_len > width {
        return Err(invalid());
    }
    let canonical = RoutingPrefix::canonicalized(ip, prefix_len);
    Ok((canonical.to_string(), canonical.ip, canonical.mask))
}

fn verify_report(report_path: &str, map_path: Option<&str>) -> Result<()> {
    let artifact = load_json_report(report_path)?;
    let expected_entries: Vec<(Vec<bool>, u32)> = artifact
        .entries
        .iter()
        .map(|entry| {
            let (_, ip, prefix_len) = canonical_consensus_prefix(&entry.ip_prefix)?;
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
    save_binary(open_output(outfile, true)?, &state, fill, output_name)?;
    Ok(())
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
    )?;
    Ok(())
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
    // Largest group first, like asmap-tool.py. The `(old, new)` tiebreak is
    // ours: python leaves equal-sized groups in set order and so reorders them
    // between runs, and sorting a `HashMap` drain by size alone did the same
    // here. Ordering the ties makes the output diffable run to run.
    reassignments.sort_by_key(|((old_asn, new_asn), addrs)| {
        (std::cmp::Reverse(addrs.len()), *old_asn, *new_asn)
    });
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

/// A single `prefix -> ASN` mapping used in claims and reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmapEntry {
    pub ip_prefix: String,
    pub asn: u32,
}

/// Snapshot claim broadcast by a participant for one epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmapClaim {
    pub epoch: u64,
    pub sender_id: String,
    pub claim_hash: String,
    pub entries: Vec<AsmapEntry>,
}

/// Validation outcome for one observed claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimObservation {
    pub epoch: u64,
    pub source_peer_id: String,
    pub sender_id: String,
    pub claim_hash: String,
    pub accepted: bool,
    pub reason: String,
}

/// Quorum-selected mapping with its vote count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusEntry {
    pub ip_prefix: String,
    pub asn: u32,
    pub votes: usize,
}

/// Consensus result persisted as JSON report and binary map.
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

#[cfg(feature = "nostr")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NostrQuorumBundle {
    announcement: Event,
    attestations: Vec<Event>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsensusReport {
    epoch: u64,
    topic: String,
    local_peer_id: String,
    threshold: usize,
    participants: Vec<String>,
    accepted_claims: usize,
    rejected_claims: BTreeMap<String, usize>,
    entries: Vec<ConsensusEntry>,
    observations: Vec<ClaimObservation>,
}

impl From<&ConsensusArtifact> for ConsensusReport {
    fn from(artifact: &ConsensusArtifact) -> Self {
        Self {
            epoch: artifact.epoch,
            topic: artifact.topic.clone(),
            local_peer_id: artifact.local_peer_id.clone(),
            threshold: artifact.threshold,
            participants: artifact.participants.clone(),
            accepted_claims: artifact.accepted_claims,
            rejected_claims: artifact.rejected_claims.clone(),
            entries: artifact.entries.clone(),
            observations: artifact.observations.clone(),
        }
    }
}

impl TryFrom<ConsensusReport> for ConsensusArtifact {
    type Error = anyhow::Error;

    fn try_from(report: ConsensusReport) -> Result<Self> {
        let mut state = ASMap::new();
        let mut entries = Vec::new();
        for entry in &report.entries {
            let (_, ip, prefix_len) = canonical_consensus_prefix(&entry.ip_prefix)?;
            entries.push((ip_to_bits(ip, prefix_len), entry.asn));
        }
        state.update_multi(entries);
        Ok(Self {
            epoch: report.epoch,
            topic: report.topic,
            local_peer_id: report.local_peer_id,
            threshold: report.threshold,
            participants: report.participants,
            accepted_claims: report.accepted_claims,
            rejected_claims: report.rejected_claims,
            entries: report.entries,
            observations: report.observations,
            map: state,
        })
    }
}

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub relay: relay::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub identify: identify::Behaviour,
    pub dcutr: dcutr::Behaviour,
}

fn build_app_swarm_with_identity(
    keypair: libp2p::identity::Keypair,
) -> Result<libp2p::Swarm<AppBehaviour>> {
    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)?
        .with_behaviour(|key, relay_behaviour| {
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

            let relay = relay::Behaviour::new(key.public().to_peer_id(), Default::default());
            let identify = identify::Behaviour::new(identify::Config::new(
                "/bitcoin-asmap-quorum/1.0.0".to_string(),
                key.public(),
            ));
            let dcutr = dcutr::Behaviour::new(key.public().to_peer_id());

            Ok(AppBehaviour {
                gossipsub,
                mdns,
                relay,
                relay_client: relay_behaviour,
                identify,
                dcutr,
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(StdDuration::from_secs(60)))
        .build();

    Ok(swarm)
}

fn build_app_swarm() -> Result<libp2p::Swarm<AppBehaviour>> {
    build_app_swarm_with_identity(libp2p::identity::Keypair::generate_ed25519())
}

/// Stateful quorum processor for claim validation and vote tallying.
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
    /// Creates a quorum engine for a target `threshold` and starting `epoch`.
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

    /// Returns the epoch currently tracked by the engine.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Advances to a new epoch and clears sender/vote state.
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

    /// Processes a claim whose source is derived from `sender_id`.
    pub fn process_claim(&mut self, claim: AsmapClaim) -> bool {
        let Ok(source) = claim.sender_id.parse::<PeerId>() else {
            return false;
        };
        self.process_claim_from_peer(claim, &source)
    }

    /// Processes a claim attributed to a concrete libp2p source peer.
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
        // One sender casts at most one vote per `(prefix, asn)`, however many
        // times it lists it. Normalizing below makes that matter: `1.2.3.4/8`
        // and `1.0.0.0/8` are now the same key, so without this a single sender
        // could reach `threshold` on its own by spelling one network two ways.
        let mut voted = HashSet::new();
        for entry in claim.entries {
            // Peer-supplied text: normalize before it becomes a vote key, so a
            // prefix carrying host bits (`1.2.3.4/8`, which v0.0.8 accepted and
            // truncated) votes for the same network as its canonical spelling
            // and lands in the report in a form `verify` will accept. A prefix
            // that is not a network at all cannot become a map entry, so it is
            // dropped here rather than being carried into the artifact.
            match canonical_consensus_prefix(&entry.ip_prefix) {
                Ok((prefix, _, _)) => {
                    if voted.insert((prefix.clone(), entry.asn)) {
                        *self.votes.entry((prefix, entry.asn)).or_insert(0) += 1;
                    }
                }
                Err(err) => warn!(
                    target: "asmap::consensus",
                    "ignoring unusable claim prefix '{}' (AS{}) from {sender_id}: {err}",
                    entry.ip_prefix, entry.asn,
                ),
            }
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

    /// Materializes the current quorum artifact for export.
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
            // Defensive: `process_claim_from_peer` already normalized every vote
            // key through `canonical_consensus_prefix`, so this cannot fail
            // today. If it ever does, the entry is dropped from the map *and*
            // from the report together — emitting it in only one of the two
            // would produce an artifact that this tool's own `verify` rejects.
            let (ip, prefix_len) = match canonical_consensus_prefix(&prefix) {
                Ok((_, ip, prefix_len)) => (ip, prefix_len),
                Err(err) => {
                    warn!(
                        target: "asmap::consensus",
                        "dropping unusable consensus prefix '{prefix}' (AS{asn}): {err}",
                    );
                    continue;
                }
            };
            entries.push((ip_to_bits(ip, prefix_len), asn));
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
    bootstrap_peers: Vec<Multiaddr>,
    relay_bootstraps: Vec<Multiaddr>,
}

struct CollectConfig {
    output: Option<String>,
    threshold: usize,
    epoch: u64,
    epoch_secs: u64,
    refresh_secs: u64,
    topic: String,
    collectors: Vec<u32>,
    bootstrap_peers: Vec<Multiaddr>,
    relay_bootstraps: Vec<Multiaddr>,
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

fn parse_multiaddr_list(value: &str) -> Result<Vec<Multiaddr>> {
    value
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|item| {
            item.parse::<Multiaddr>()
                .with_context(|| format!("invalid multiaddr '{item}'"))
        })
        .collect()
}

fn default_bootstrap_peers(cfg_bootstrap: &[Multiaddr]) -> Result<Vec<Multiaddr>> {
    let mut peers = IPFS_BOOTSTRAP_NODES
        .iter()
        .map(|addr| {
            addr.parse::<Multiaddr>()
                .with_context(|| format!("invalid default bootstrap multiaddr '{addr}'"))
        })
        .collect::<Result<Vec<_>>>()?;
    peers.extend(cfg_bootstrap.iter().cloned());
    Ok(peers)
}

fn parse_serve_args(args: &[String]) -> Result<ServeConfig> {
    let mut input = None;
    let mut output = None;
    let mut threshold = 3usize;
    let mut epoch = 1u64;
    let mut epoch_secs = 60u64;
    let mut topic = String::from("bitcoin-asmap-quorum");
    let mut bootstrap_peers = Vec::new();
    let mut relay_bootstraps = Vec::new();
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
            "--bootstrap" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                bootstrap_peers.extend(parse_multiaddr_list(value)?);
            }
            "--relay" | "--bootstrap-relay" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                relay_bootstraps.extend(parse_multiaddr_list(value)?);
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
        bootstrap_peers,
        relay_bootstraps,
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
    let mut bootstrap_peers = Vec::new();
    let mut relay_bootstraps = Vec::new();

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
            "--bootstrap" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                bootstrap_peers.extend(parse_multiaddr_list(value)?);
            }
            "--relay" | "--bootstrap-relay" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                relay_bootstraps.extend(parse_multiaddr_list(value)?);
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
        bootstrap_peers,
        relay_bootstraps,
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

    let mut swarm = build_app_swarm()?;

    let topic_name = cfg.topic.clone();
    let topic = gossipsub::IdentTopic::new(topic_name.clone());
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    for addr in default_bootstrap_peers(&cfg.bootstrap_peers)? {
        info!(target: "asmap::serve", "dialing bootstrap peer {}", addr);
        if let Err(err) = swarm.dial(addr.clone()) {
            warn!(target: "asmap::serve", "failed to dial bootstrap peer {}: {err}", addr);
        }
    }
    for relay_addr in &cfg.relay_bootstraps {
        info!(target: "asmap::serve", "connecting through relay {}", relay_addr);
        if let Err(err) = swarm.dial(relay_addr.clone()) {
            warn!(target: "asmap::serve", "failed to dial relay {}: {err}", relay_addr);
            continue;
        }
        let relay_listen = relay_addr.clone().with(Protocol::P2pCircuit);
        if let Err(err) = swarm.listen_on(relay_listen.clone()) {
            warn!(target: "asmap::serve", "failed to listen on relay circuit {}: {err}", relay_listen);
        }
    }

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
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!(target: "asmap::serve", "listening on {}", address);
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    debug!(target: "asmap::serve", "discovered {} mdns peers", list.len());
                    for (peer_id, _multiaddr) in list {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                    info!(target: "asmap::serve", "observed address {}", info.observed_addr);
                    swarm.add_external_address(info.observed_addr.clone());
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                    debug!(target: "asmap::serve", "relay client event: {event:?}");
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Relay(event)) => {
                    debug!(target: "asmap::serve", "relay server event: {event:?}");
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Dcutr(event)) => {
                    debug!(target: "asmap::serve", "dcutr event: {event:?}");
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

    let mut swarm = build_app_swarm()?;

    let topic_name = cfg.topic.clone();
    let topic = gossipsub::IdentTopic::new(topic_name.clone());
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    for addr in default_bootstrap_peers(&cfg.bootstrap_peers)? {
        info!(target: "asmap::collect", "dialing bootstrap peer {}", addr);
        if let Err(err) = swarm.dial(addr.clone()) {
            warn!(target: "asmap::collect", "failed to dial bootstrap peer {}: {err}", addr);
        }
    }
    for relay_addr in &cfg.relay_bootstraps {
        info!(target: "asmap::collect", "connecting through relay {}", relay_addr);
        if let Err(err) = swarm.dial(relay_addr.clone()) {
            warn!(target: "asmap::collect", "failed to dial relay {}: {err}", relay_addr);
            continue;
        }
        let relay_listen = relay_addr.clone().with(Protocol::P2pCircuit);
        if let Err(err) = swarm.listen_on(relay_listen.clone()) {
            warn!(target: "asmap::collect", "failed to listen on relay circuit {}: {err}", relay_listen);
        }
    }

    let mut engine = QuorumEngine::new(cfg.threshold, cfg.epoch);
    let mut publish_timer = interval(StdDuration::from_secs(5));
    let mut refresh_timer = interval(StdDuration::from_secs(cfg.refresh_secs));
    let mut epoch_timer = interval(StdDuration::from_secs(cfg.epoch_secs));
    let local_peer_id = swarm.local_peer_id().to_string();
    let mut known_peers: HashSet<String> = HashSet::new();
    let local_assignment = assigned_collectors(&cfg.collectors, &local_peer_id, &known_peers);
    info!(
        target: "asmap::collect",
        "initial collector assignment for {}: {:?}",
        local_peer_id,
        local_assignment
    );
    let local_claim_template =
        build_ris_claim(local_assignment.clone(), cfg.epoch, local_peer_id.clone()).await?;
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
                let current_assignment = assigned_collectors(&cfg.collectors, &local_peer_id, &known_peers);
                trace!(target: "asmap::collect", "current collector assignment: {:?}", current_assignment);
                match build_ris_claim(current_assignment, engine.epoch(), local_peer_id.clone()).await {
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
                let current_assignment = assigned_collectors(&cfg.collectors, &local_peer_id, &known_peers);
                trace!(target: "asmap::collect", "current collector assignment: {:?}", current_assignment);
                match build_ris_claim(current_assignment, next_epoch, local_peer_id.clone()).await {
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
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!(target: "asmap::collect", "listening on {}", address);
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(event)) => {
                    match event {
                        mdns::Event::Discovered(list) => {
                            debug!(target: "asmap::collect", "discovered {} mdns peers", list.len());
                            for (peer_id, _multiaddr) in list {
                                known_peers.insert(peer_id.to_string());
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            }
                        }
                        mdns::Event::Expired(list) => {
                            debug!(target: "asmap::collect", "expired {} mdns peers", list.len());
                            for (peer_id, _multiaddr) in list {
                                known_peers.remove(&peer_id.to_string());
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                    info!(target: "asmap::collect", "observed address {}", info.observed_addr);
                    swarm.add_external_address(info.observed_addr.clone());
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                    debug!(target: "asmap::collect", "relay client event: {event:?}");
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Relay(event)) => {
                    debug!(target: "asmap::collect", "relay server event: {event:?}");
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Dcutr(event)) => {
                    debug!(target: "asmap::collect", "dcutr event: {event:?}");
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

fn snapshot_sender_id(prefix: &str, path: &str, idx: usize) -> Result<String> {
    let stem = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("snapshot");
    let seed_material = format!("{prefix}:{stem}:{idx}");
    let digest = Sha256::digest(seed_material.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    let keypair = libp2p::identity::Keypair::ed25519_from_bytes(seed)
        .map_err(|err| anyhow!("failed to derive sender keypair: {err}"))?;
    Ok(keypair.public().to_peer_id().to_string())
}

fn run_import(args: &[String]) -> Result<()> {
    let cfg = parse_import_args(args)?;
    let mut claims = Vec::new();
    for (idx, input) in cfg.inputs.iter().enumerate() {
        let state = load_file(open_input(Some(input))?, input)?;
        let sender_id = snapshot_sender_id(&cfg.sender_prefix, input, idx)?;
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

impl RoutingPrefix {
    /// Clears any host bits below the mask boundary, so the prefix is safe to
    /// hand to `ip_to_bits`. An out-of-range mask is left alone; the address is
    /// then already canonical for every bit `ip_to_bits` will read.
    fn canonicalized(ip: IpAddr, mask: u8) -> Self {
        let ip = match ip {
            IpAddr::V4(v4) if mask < 32 => {
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & !(u32::MAX >> mask)))
            }
            IpAddr::V6(v6) if mask < 128 => IpAddr::V6(Ipv6Addr::from(
                u128::from_be_bytes(v6.octets()) & !(u128::MAX >> mask),
            )),
            other => other,
        };
        Self { ip, mask }
    }
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
        // Every `RoutingPrefix` must be canonical no matter how it was built:
        // `to_asmap` feeds `ip` and `mask` straight to `ip_to_bits`, which
        // `debug_assert!`s on host bits. Constructing `Self { ip, mask }` here
        // would panic in debug builds and truncate in release ones.
        Ok(Self::canonicalized(ip, mask))
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
        // MRT carries only the significant bytes of a prefix, so the zero-padded
        // address is normally canonical already. A malformed source can still
        // leave host bits set inside the final byte; mask them off here so
        // `to_asmap`'s `ip_to_bits` never sees a non-canonical prefix.
        //
        // For every well-formed dump this is a no-op. For a malformed one it is
        // NOT purely cosmetic, because the value is a `HashMap` key: two RIB
        // prefixes that differ only in host bits (`1.2.3.0/24` and
        // `1.2.3.128/24`) used to be distinct keys and now collapse into one, so
        // their AS-path lists are pooled before `find_common_suffix` runs and a
        // single bottleneck ASN is derived. Previously they stayed separate,
        // produced two bottleneck ASNs, and then collided anyway inside
        // `to_asmap` — where `ip_to_bits` truncated both to the same prefix bits
        // and `update_multi` let an arbitrary one win by `HashMap` iteration
        // order. Pooling is the deterministic reading of the same broken input.
        let routing_prefix = RoutingPrefix::canonicalized(ip, mask);
        if routing_prefix.ip != ip {
            warn!(
                target: "asmap::mrt",
                "MRT prefix {ip}/{mask} has host bits set; masking to {routing_prefix}",
            );
        }
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

fn usage(binary_name: &str) {
    eprintln!(
        "Usage:\n  {binary_name} encode [-f|--fill] [infile] [outfile]\n  {binary_name} decode [-f|--fill] [-n|--nonoverlapping] [infile] [outfile]\n  {binary_name} diff [-i|--ignore-unassigned] infile1 infile2\n  {binary_name} diff_addrs [-s|--show-addresses] infile1 infile2 addrs_file\n  {binary_name} import [--epoch N] [--sender-prefix PREFIX] [--output FILE] snapshot1 [snapshot2...]\n  {binary_name} serve [--threshold N] [--epoch N] [--epoch-secs N] [--topic NAME] [--bootstrap ADDR[,ADDR...]] [--relay ADDR[,ADDR...]] [infile] [outfile]\n  {binary_name} collect [--threshold N] [--epoch N] [--epoch-secs N] [--refresh-secs N] [--topic NAME] [-n 0,1,2] [--bootstrap ADDR[,ADDR...]] [--relay ADDR[,ADDR...]] [--output FILE]\n  {binary_name} replay [--threshold N] [--epoch N] [--topic NAME] [--local-peer-id ID] [--output FILE] [--report FILE] claims.jsonl\n  {binary_name} compare report1.json report2.json\n  {binary_name} download [-o OUT] [-n 0,1,2]\n  {binary_name} find-bottleneck -d DIR [-o OUT]\n  {binary_name} verify report.json [mapfile]"
    );
}

/// CLI entrypoint shared by both binaries in this repository.
pub fn run() -> Result<()> {
    let binary_name = option_env!("CARGO_BIN_NAME")
        .or(option_env!("CARGO_PKG_NAME"))
        .unwrap_or("bitcoin-asmap-quorum");
    run_with_binary_name(binary_name)
}

/// CLI entrypoint with an explicit binary name for usage output.
pub fn run_with_binary_name(binary_name: &str) -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage(binary_name);
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
                usage(binary_name);
                bail!("verify requires a report file");
            }
            verify_report(&args[0], args.get(1).map(String::as_str))
        }
        "serve" => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_serve_async(&args))
        }
        _ => {
            usage(binary_name);
            bail!("unknown subcommand '{cmd}'")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::net::Ipv4Addr;

    fn temp_path(stem: &str, ext: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("bitcoin_asmap_{stem}_{pid}_{nanos}.{ext}"))
    }

    fn write_text(path: &std::path::Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
    }

    fn cleanup(paths: &[&std::path::Path]) {
        for path in paths {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Serializes the network-touching tests against each other.
    ///
    /// Async-aware on purpose: the guard is deliberately held across `.await`
    /// points for the whole duration of a swarm test, which a
    /// `std::sync::Mutex` guard must never be (`clippy::await_holding_lock`).
    fn network_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn test_keypair(seed: &str) -> libp2p::identity::Keypair {
        let digest = Sha256::digest(seed.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        libp2p::identity::Keypair::ed25519_from_bytes(bytes)
            .expect("deterministic test identity must be valid")
    }

    fn build_test_swarm(seed: &str) -> anyhow::Result<libp2p::Swarm<AppBehaviour>> {
        build_app_swarm_with_identity(test_keypair(seed))
    }

    async fn wait_for_listen_addr(
        swarm: &mut libp2p::Swarm<AppBehaviour>,
        label: &str,
        expected_fragment: &str,
    ) -> anyhow::Result<Multiaddr> {
        let fut = async {
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("[libp2p] {label} listen address: {address}");
                        if address.to_string().contains(expected_fragment) {
                            return Ok(address);
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] {label} connection established with {peer_id}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(
                        identify::Event::Received { info, .. },
                    )) => {
                        println!(
                            "[libp2p] {label} identify received {} listen addrs",
                            info.listen_addrs.len()
                        );
                    }
                    _ => {}
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(20), fut)
            .await
            .context("timed out waiting for listen address")?
    }

    fn make_claim(epoch: u64, sender_id: String, entries: Vec<AsmapEntry>) -> AsmapClaim {
        let claim_hash = claim_hash(epoch, &sender_id, &entries);
        AsmapClaim {
            epoch,
            sender_id,
            claim_hash,
            entries,
        }
    }

    fn relay_bootstrap_addr(
        relay_addr: &Multiaddr,
        relay_peer_id: &PeerId,
    ) -> anyhow::Result<Multiaddr> {
        format!("{relay_addr}/p2p/{relay_peer_id}")
            .parse::<Multiaddr>()
            .context("invalid relay bootstrap address")
    }

    fn relay_bootstrap_candidates() -> anyhow::Result<Vec<Multiaddr>> {
        if let Ok(value) = std::env::var("ASMAP_RELAY_BOOTSTRAPS") {
            let relays = parse_multiaddr_list(&value)?;
            if !relays.is_empty() {
                return Ok(relays);
            }
        }

        IPFS_BOOTSTRAP_NODES
            .iter()
            .map(|addr| {
                addr.parse::<Multiaddr>()
                    .with_context(|| format!("invalid default relay bootstrap multiaddr '{addr}'"))
            })
            .collect()
    }

    async fn run_relay_gossipsub_roundtrip_with_bootstrap(
        relay_bootstrap: Multiaddr,
    ) -> anyhow::Result<()> {
        let mut dialer = build_test_swarm("relay-dialer")?;
        let mut listener = build_test_swarm("relay-listener")?;
        let topic = gossipsub::IdentTopic::new("libp2p-relay-gossipsub");

        println!(
            "[libp2p] probe relay bootstrap={} dialer={} listener={}",
            relay_bootstrap,
            dialer.local_peer_id(),
            listener.local_peer_id()
        );
        dialer.behaviour_mut().gossipsub.subscribe(&topic)?;
        listener.behaviour_mut().gossipsub.subscribe(&topic)?;

        let (dummy_text, dummy_binary, payload) = dummy_asmap_payload();
        println!("[libp2p] relay payload text: {dummy_text}");
        println!(
            "[libp2p] relay payload binary bytes: {}",
            dummy_binary.len()
        );
        println!(
            "[libp2p] relay payload json: {}",
            String::from_utf8_lossy(&payload)
        );

        let listener_peer = *listener.local_peer_id();
        let dialer_peer = *dialer.local_peer_id();
        let listener_addr = relay_bootstrap
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(listener_peer));
        let dialer_addr = relay_bootstrap
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(dialer_peer));

        listener.listen_on(listener_addr.clone())?;
        dialer.listen_on(dialer_addr.clone())?;
        println!("[libp2p] listener relay addr: {listener_addr}");
        println!("[libp2p] dialer relay addr: {dialer_addr}");

        let reservation_deadline = tokio::time::sleep(std::time::Duration::from_secs(30));
        tokio::pin!(reservation_deadline);
        let mut listener_reserved = false;
        let mut dialer_reserved = false;

        while !(listener_reserved && dialer_reserved) {
            tokio::select! {
                _ = &mut reservation_deadline => anyhow::bail!("timed out waiting for relay reservations"),
                event = listener.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] listener connected to {peer_id}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                        println!("[libp2p] listener relay-client event: {event:?}");
                        if matches!(event, relay::client::Event::ReservationReqAccepted { .. }) {
                            listener_reserved = true;
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] listener identify received {} listen addrs", info.listen_addrs.len());
                    }
                    _ => {}
                },
                event = dialer.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] dialer connected to {peer_id}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                        println!("[libp2p] dialer relay-client event: {event:?}");
                        if matches!(event, relay::client::Event::ReservationReqAccepted { .. }) {
                            dialer_reserved = true;
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] dialer identify received {} listen addrs", info.listen_addrs.len());
                    }
                    _ => {}
                },
            }
        }

        println!("[libp2p] relay reservations ready; dialing listener via public relay");
        dialer.dial(listener_addr.clone())?;

        let deadline = tokio::time::sleep(std::time::Duration::from_secs(45));
        tokio::pin!(deadline);
        let mut dialer_connected = false;
        let mut listener_connected = false;
        let mut message_seen = false;
        let mut published = false;

        loop {
            tokio::select! {
                _ = &mut deadline => anyhow::bail!("timed out waiting for relay-backed gossipsub message"),
                event = dialer.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] dialer connected to {peer_id}");
                        if peer_id == *listener.local_peer_id() {
                            dialer_connected = true;
                            dialer.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] dialer identify received {} listen addrs", info.listen_addrs.len());
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message,
                        ..
                    })) => {
                        println!(
                            "[libp2p] dialer got gossipsub message from {propagation_source} ({} bytes)",
                            message.data.len()
                        );
                    }
                    _ => {}
                },
                event = listener.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] listener connected to {peer_id}");
                        if peer_id == *dialer.local_peer_id() {
                            listener_connected = true;
                            listener.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] listener identify received {} listen addrs", info.listen_addrs.len());
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message,
                        ..
                    })) => {
                        println!(
                            "[libp2p] listener got gossipsub message from {propagation_source} ({} bytes)",
                            message.data.len()
                        );
                        assert_eq!(propagation_source, *dialer.local_peer_id());
                        assert_eq!(message.data, payload);
                        message_seen = true;
                    }
                    _ => {}
                },
            }

            if dialer_connected && listener_connected && message_seen {
                break;
            }

            if dialer_connected && listener_connected && !published {
                match dialer
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), payload.clone())
                {
                    Ok(_) => {
                        println!("[libp2p] dialer sent gossipsub payload");
                        published = true;
                    }
                    Err(gossipsub::PublishError::InsufficientPeers) => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }

        Ok(())
    }

    async fn run_relay_gossipsub_roundtrip_local() -> anyhow::Result<()> {
        let mut relay = build_test_swarm("relay-server")?;
        let mut dialer = build_test_swarm("relay-dialer")?;
        let mut listener = build_test_swarm("relay-listener")?;
        let topic = gossipsub::IdentTopic::new("libp2p-relay-gossipsub");

        println!(
            "[libp2p] relay server={} dialer={} listener={}",
            relay.local_peer_id(),
            dialer.local_peer_id(),
            listener.local_peer_id()
        );
        dialer.behaviour_mut().gossipsub.subscribe(&topic)?;
        listener.behaviour_mut().gossipsub.subscribe(&topic)?;

        relay.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
        let relay_tcp = wait_for_listen_addr(&mut relay, "relay", "/tcp/").await?;
        relay.add_external_address(relay_tcp.clone());
        let relay_bootstrap = relay_bootstrap_addr(&relay_tcp, relay.local_peer_id())?;
        println!("[libp2p] relay bootstrap addr: {relay_bootstrap}");

        let (dummy_text, dummy_binary, payload) = dummy_asmap_payload();
        println!("[libp2p] relay payload text: {dummy_text}");
        println!(
            "[libp2p] relay payload binary bytes: {}",
            dummy_binary.len()
        );
        println!(
            "[libp2p] relay payload json: {}",
            String::from_utf8_lossy(&payload)
        );
        let listener_peer = *listener.local_peer_id();
        let dialer_peer = *dialer.local_peer_id();
        let relay_peer = *relay.local_peer_id();

        let listener_addr = relay_bootstrap
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(listener_peer));
        let dialer_addr = relay_bootstrap
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(dialer_peer));

        listener.listen_on(listener_addr.clone())?;
        dialer.listen_on(dialer_addr.clone())?;
        println!("[libp2p] listener relay addr: {listener_addr}");
        println!("[libp2p] dialer relay addr: {dialer_addr}");

        let reservation_deadline = tokio::time::sleep(std::time::Duration::from_secs(30));
        tokio::pin!(reservation_deadline);
        let mut listener_reserved = false;
        let mut dialer_reserved = false;

        while !(listener_reserved && dialer_reserved) {
            tokio::select! {
                _ = &mut reservation_deadline => anyhow::bail!("timed out waiting for relay reservations"),
                event = relay.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] relay connected to {peer_id}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Relay(event)) => {
                        println!("[libp2p] relay server relay event: {event:?}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                        println!("[libp2p] relay server relay-client event: {event:?}");
                    }
                    _ => {}
                },
                event = listener.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] listener connected to {peer_id}");
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("[libp2p] listener new listen addr: {address}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                        println!("[libp2p] listener relay-client event: {event:?}");
                        if matches!(event, relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } if relay_peer_id == relay_peer) {
                            listener_reserved = true;
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] listener identify received {} listen addrs", info.listen_addrs.len());
                    }
                    _ => {}
                },
                event = dialer.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] dialer connected to {peer_id}");
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("[libp2p] dialer new listen addr: {address}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                        println!("[libp2p] dialer relay-client event: {event:?}");
                        if matches!(event, relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } if relay_peer_id == relay_peer) {
                            dialer_reserved = true;
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] dialer identify received {} listen addrs", info.listen_addrs.len());
                    }
                    _ => {}
                },
            }
        }

        println!("[libp2p] relay reservations ready; dialing listener via relay");
        dialer.dial(listener_addr.clone())?;

        let deadline = tokio::time::sleep(std::time::Duration::from_secs(45));
        tokio::pin!(deadline);
        let mut dialer_connected = false;
        let mut listener_connected = false;
        let mut message_seen = false;
        let mut published = false;

        loop {
            tokio::select! {
                _ = &mut deadline => anyhow::bail!("timed out waiting for relay-backed gossipsub message"),
                event = relay.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] relay connected to {peer_id}");
                        if peer_id == dialer_peer || peer_id == listener_peer {
                            // nothing else to do here
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Relay(event)) => {
                        println!("[libp2p] relay server relay event: {event:?}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                        println!("[libp2p] relay server relay-client event: {event:?}");
                    }
                    _ => {}
                },
                event = dialer.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] dialer connected to {peer_id}");
                        if peer_id == listener_peer {
                            dialer_connected = true;
                            dialer.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("[libp2p] dialer new listen addr: {address}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message,
                        ..
                    })) => {
                        println!(
                            "[libp2p] dialer got gossipsub message from {propagation_source} ({} bytes)",
                            message.data.len()
                        );
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                        println!("[libp2p] dialer relay-client event: {event:?}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] dialer identify received {} listen addrs", info.listen_addrs.len());
                    }
                    _ => {}
                },
                event = listener.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] listener connected to {peer_id}");
                        if peer_id == dialer_peer {
                            listener_connected = true;
                            listener.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("[libp2p] listener new listen addr: {address}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                        println!("[libp2p] listener relay-client event: {event:?}");
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] listener identify received {} listen addrs", info.listen_addrs.len());
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message,
                        ..
                    })) => {
                        println!(
                            "[libp2p] listener got gossipsub message from {propagation_source} ({} bytes)",
                            message.data.len()
                        );
                        assert_eq!(propagation_source, dialer_peer);
                        assert_eq!(message.data, payload);
                        message_seen = true;
                    }
                    _ => {}
                },
            }

            if dialer_connected && listener_connected && message_seen {
                break;
            }

            if dialer_connected && listener_connected && !published {
                match dialer
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), payload.clone())
                {
                    Ok(_) => {
                        println!("[libp2p] dialer sent gossipsub payload");
                        published = true;
                    }
                    Err(gossipsub::PublishError::InsufficientPeers) => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }

        Ok(())
    }

    fn dummy_asmap_payload() -> (String, Vec<u8>, Vec<u8>) {
        let text = "1.2.3.0/24 AS64512\n2.3.4.0/24 AS64513\n".to_string();
        let mut map = ASMap::new();
        map.update_multi(vec![
            (ip_to_bits("1.2.3.0".parse::<IpAddr>().unwrap(), 24), 64512),
            (ip_to_bits("2.3.4.0".parse::<IpAddr>().unwrap(), 24), 64513),
        ]);
        let binary = map.to_binary(false);
        let payload = serde_json::json!({
            "human_readable": text,
            "binary_hex": hex::encode(&binary),
        });
        (text, binary, serde_json::to_vec(&payload).unwrap())
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
                    let (ip, prefix_len) =
                        asmap_codec::parse_network_prefix(&entry.ip_prefix).unwrap();
                    (ip_to_bits(ip, prefix_len), entry.asn)
                })
                .collect::<Vec<_>>();
            state.update_multi(entries);
            state
        };
        assert_eq!(rebuilt, artifact.map);
    }

    #[test]
    fn non_canonical_claim_prefix_is_normalized_and_stays_verifiable() {
        // Regression: a peer-supplied prefix with host bits set used to be
        // dropped from the map but still written into the report, so `replay`
        // emitted an artifact that this tool's own `verify` refused to parse.
        let sender = PeerId::random();
        let claim = make_claim(
            7,
            sender.to_string(),
            vec![AsmapEntry {
                ip_prefix: "1.2.3.4/8".to_string(),
                asn: 64512,
            }],
        );
        let mut engine = QuorumEngine::new(1, 7);
        assert!(engine.process_claim(claim));
        let artifact = engine.finalize("bitcoin-asmap-quorum", &PeerId::random().to_string());
        assert_eq!(artifact.entries.len(), 1);
        assert_eq!(artifact.entries[0].ip_prefix, "1.0.0.0/8");
        // What `verify_report` does: rebuild the map from the report entries.
        let round_trip = ConsensusArtifact::try_from(ConsensusReport::from(&artifact)).unwrap();
        assert_eq!(round_trip.map, artifact.map);
        assert!(!artifact.map.to_entries(false, false).is_empty());
    }

    #[test]
    fn unparseable_claim_prefix_never_reaches_the_artifact() {
        let sender = PeerId::random();
        let claim = make_claim(
            7,
            sender.to_string(),
            vec![
                AsmapEntry {
                    ip_prefix: "not-a-network".to_string(),
                    asn: 7,
                },
                AsmapEntry {
                    ip_prefix: "10.0.0.0/8".to_string(),
                    asn: 9,
                },
            ],
        );
        let mut engine = QuorumEngine::new(1, 7);
        assert!(engine.process_claim(claim));
        let artifact = engine.finalize("bitcoin-asmap-quorum", &PeerId::random().to_string());
        assert_eq!(artifact.entries.len(), 1);
        assert_eq!(artifact.entries[0].ip_prefix, "10.0.0.0/8");
        assert_eq!(
            ConsensusArtifact::try_from(ConsensusReport::from(&artifact))
                .unwrap()
                .map,
            artifact.map
        );
    }

    #[test]
    fn one_sender_cannot_double_vote_the_same_prefix() {
        let sender = PeerId::random();
        let claim = make_claim(
            7,
            sender.to_string(),
            vec![
                AsmapEntry {
                    ip_prefix: "1.2.3.4/8".to_string(),
                    asn: 64512,
                },
                AsmapEntry {
                    ip_prefix: "1.0.0.0/8".to_string(),
                    asn: 64512,
                },
            ],
        );
        let mut engine = QuorumEngine::new(2, 7);
        // Threshold 2 with a single sender: no prefix may reach quorum.
        assert!(!engine.process_claim(claim));
        let artifact = engine.finalize("bitcoin-asmap-quorum", &PeerId::random().to_string());
        assert!(artifact.entries.is_empty());
    }

    #[test]
    fn v0_0_8_report_with_host_bits_still_loads() {
        // v0.0.8 wrote un-masked prefixes (find-bottleneck built RoutingPrefix
        // without masking) and its reader truncated them silently inside
        // `ip_to_bits`. Those artifacts must keep loading now the codec is
        // strict.
        let legacy = ConsensusReport {
            epoch: 7,
            topic: "bitcoin-asmap-quorum".to_string(),
            local_peer_id: "offline-replay".to_string(),
            threshold: 1,
            participants: Vec::new(),
            accepted_claims: 1,
            rejected_claims: BTreeMap::new(),
            entries: vec![ConsensusEntry {
                ip_prefix: "1.2.3.4/8".to_string(),
                asn: 64512,
                votes: 1,
            }],
            observations: Vec::new(),
        };
        let artifact = ConsensusArtifact::try_from(legacy).expect("legacy report must load");
        let mut expected = ASMap::new();
        expected.update_multi(vec![(ip_to_bits("1.0.0.0".parse().unwrap(), 8), 64512u32)]);
        assert_eq!(artifact.map, expected);
    }

    #[tokio::test]
    #[cfg(feature = "nostr")]
    async fn nostr_sidecar_emits_quorum_announcement_and_attestations() {
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
        let mut engine = QuorumEngine::new(2, 7);
        assert!(!engine.process_claim(claim_a));
        assert!(engine.process_claim(claim_b));
        let artifact = engine.finalize("bitcoin-asmap-quorum", "coordinator-1");

        let report = temp_path("nostr_sidecar_report", "json");
        save_json_report(&report, &artifact).unwrap();

        let sidecar = report.with_extension("nostr.json");
        let raw = std::fs::read_to_string(&sidecar).unwrap();
        let bundle: NostrQuorumBundle = serde_json::from_str(&raw).unwrap();
        assert_eq!(bundle.announcement.kind, Kind::GitIssue);
        assert!(!bundle.announcement.sig.to_hex().is_empty());
        assert!(!bundle.announcement.tags.is_empty());
        assert_eq!(bundle.attestations.len(), artifact.participants.len());
        assert!(
            bundle
                .attestations
                .iter()
                .all(|event| event.kind == Kind::Comment && !event.sig.to_hex().is_empty())
        );
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

    #[test]
    fn workflow_import_replay_verify_roundtrips_real_files() {
        let claims = temp_path("claims", "json");
        let map = temp_path("consensus", "map");
        let report = temp_path("consensus", "json");
        let mut snapshots = Vec::new();
        let base_snapshot = "1.2.3.0/24 AS64512\n2.3.4.0/24 AS64513\n";
        let noisy_snapshot = "1.2.3.0/24 AS64512\n2.3.4.0/24 AS64513\n3.4.5.0/24 AS64514\n";

        println!("[lifecycle] stage 1: write peer snapshots for 100 nodes");
        for idx in 0..100 {
            let snapshot = temp_path(&format!("snapshot_{idx}"), "txt");
            write_text(
                &snapshot,
                if idx < 90 {
                    base_snapshot
                } else {
                    noisy_snapshot
                },
            );
            snapshots.push(snapshot);
        }

        println!("[lifecycle] stage 2: import snapshots into claim batch");
        let mut import_args = vec![
            "-e".to_string(),
            "42".to_string(),
            "--sender-prefix".to_string(),
            "node".to_string(),
            "-o".to_string(),
            claims.to_string_lossy().into_owned(),
        ];
        import_args.extend(
            snapshots
                .iter()
                .map(|snapshot| snapshot.to_string_lossy().into_owned()),
        );
        run_import(&import_args).unwrap();

        let imported = load_claims(claims.to_str().unwrap()).unwrap();
        assert_eq!(imported.len(), 100);
        assert_eq!(
            imported
                .iter()
                .map(|claim| claim.sender_id.clone())
                .collect::<HashSet<_>>()
                .len(),
            100
        );
        assert!(
            imported
                .iter()
                .all(|claim| claim.sender_id.parse::<PeerId>().is_ok())
        );
        println!(
            "[lifecycle] imported {} claims from {}",
            imported.len(),
            claims.display()
        );

        println!("[lifecycle] stage 3: replay claims into consensus artifact");
        run_replay(&[
            "-t".to_string(),
            "67".to_string(),
            "-e".to_string(),
            "42".to_string(),
            "--topic".to_string(),
            "workflow".to_string(),
            "--output".to_string(),
            map.to_string_lossy().into_owned(),
            "--report".to_string(),
            report.to_string_lossy().into_owned(),
            claims.to_string_lossy().into_owned(),
        ])
        .unwrap();

        let artifact = load_json_report(report.to_str().unwrap()).unwrap();
        assert_eq!(artifact.threshold, 67);
        assert_eq!(artifact.accepted_claims, 100);
        assert_eq!(artifact.entries.len(), 2);
        println!(
            "[lifecycle] consensus epoch={} participants={} entries={} accepted={}",
            artifact.epoch,
            artifact.participants.len(),
            artifact.entries.len(),
            artifact.accepted_claims
        );
        for entry in &artifact.entries {
            println!(
                "[lifecycle] consensus {} -> AS{} (votes={})",
                entry.ip_prefix, entry.asn, entry.votes
            );
        }

        println!("[lifecycle] stage 4: verify the emitted report and map");
        verify_report(report.to_str().unwrap(), Some(map.to_str().unwrap())).unwrap();
        println!("[lifecycle] verification complete");

        for snapshot in &snapshots {
            let _ = std::fs::remove_file(snapshot);
        }
        cleanup(&[claims.as_path(), map.as_path(), report.as_path()]);
    }

    #[test]
    fn collector_assignment_partitions_work_across_peers() {
        let collectors = (0..100).collect::<Vec<_>>();
        let peers = (0..100)
            .map(|_| PeerId::random().to_string())
            .collect::<Vec<_>>();

        let mut all_assigned = Vec::new();
        for (idx, peer) in peers.iter().enumerate() {
            let known: HashSet<String> = peers
                .iter()
                .enumerate()
                .filter_map(|(j, p)| if j != idx { Some(p.clone()) } else { None })
                .collect();
            let assigned = assigned_collectors(&collectors, peer, &known);
            assert!(!assigned.is_empty());
            all_assigned.extend(assigned);
        }
        all_assigned.sort();
        assert_eq!(all_assigned, collectors);
    }

    #[test]
    fn bootstrap_arguments_parse_pinned_multiaddrs() {
        let relay_peer = PeerId::random();
        let seed_peer = PeerId::random();
        let args = vec![
            "--bootstrap".to_string(),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", seed_peer),
            "--relay".to_string(),
            format!("/ip4/127.0.0.1/tcp/4002/p2p/{}", relay_peer),
            "input.asmap".to_string(),
            "output.asmap".to_string(),
        ];

        let serve = parse_serve_args(&args).unwrap();
        assert_eq!(serve.bootstrap_peers.len(), 1);
        assert_eq!(serve.relay_bootstraps.len(), 1);
        assert_eq!(serve.input.as_deref(), Some("input.asmap"));
        assert_eq!(serve.output.as_deref(), Some("output.asmap"));

        let collect = parse_collect_args(&args).unwrap();
        assert_eq!(collect.bootstrap_peers.len(), 1);
        assert_eq!(collect.relay_bootstraps.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg_attr(not(feature = "expensive_tests"), ignore)]
    async fn libp2p_stack_bootstraps_tcp_and_quic() -> anyhow::Result<()> {
        let _guard = network_lock().lock().await;
        let mut swarm = build_test_swarm("stack-bootstrap")?;

        println!(
            "[libp2p] bootstrapping stack for peer {}",
            swarm.local_peer_id()
        );
        swarm.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
        swarm.listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;

        let tcp = wait_for_listen_addr(&mut swarm, "tcp", "/tcp/").await?;
        let quic = wait_for_listen_addr(&mut swarm, "quic", "/quic-v1").await?;

        println!("[libp2p] tcp listen addr: {tcp}");
        println!("[libp2p] quic listen addr: {quic}");
        assert!(tcp.to_string().contains("/tcp/"));
        assert!(quic.to_string().contains("/quic-v1"));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg_attr(not(feature = "expensive_tests"), ignore)]
    async fn libp2p_quic_identify_roundtrip() -> anyhow::Result<()> {
        let _guard = network_lock().lock().await;
        let mut dialer = build_test_swarm("quic-dialer")?;
        let mut listener = build_test_swarm("quic-listener")?;

        println!(
            "[libp2p] quic dialer={} listener={}",
            dialer.local_peer_id(),
            listener.local_peer_id()
        );
        listener.listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;
        let listener_addr = wait_for_listen_addr(&mut listener, "listener", "/quic-v1").await?;

        dialer.listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;
        let _ = wait_for_listen_addr(&mut dialer, "dialer", "/quic-v1").await?;
        dialer.dial(listener_addr.clone())?;
        println!("[libp2p] dialling quic addr {listener_addr}");

        let deadline = tokio::time::sleep(std::time::Duration::from_secs(30));
        tokio::pin!(deadline);
        let mut dialer_connected = false;
        let mut listener_connected = false;
        let mut dialer_identified = false;
        let mut listener_identified = false;

        loop {
            tokio::select! {
                _ = &mut deadline => anyhow::bail!("timed out waiting for quic connection"),
                event = dialer.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] dialer connected to {peer_id}");
                        if peer_id == *listener.local_peer_id() {
                            dialer_connected = true;
                            dialer.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] dialer identify received {} listen addrs", info.listen_addrs.len());
                        dialer_identified = true;
                    }
                    _ => {}
                },
                event = listener.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] listener connected to {peer_id}");
                        if peer_id == *dialer.local_peer_id() {
                            listener_connected = true;
                            listener.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] listener identify received {} listen addrs", info.listen_addrs.len());
                        listener_identified = true;
                    }
                    _ => {}
                },
            }

            if dialer_connected && listener_connected && dialer_identified && listener_identified {
                break;
            }
        }

        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg_attr(not(feature = "expensive_tests"), ignore)]
    async fn libp2p_tcp_gossipsub_roundtrip() -> anyhow::Result<()> {
        let _guard = network_lock().lock().await;
        let mut publisher = build_test_swarm("tcp-publisher")?;
        let mut subscriber = build_test_swarm("tcp-subscriber")?;
        let topic = gossipsub::IdentTopic::new("libp2p-stack-gossipsub");

        println!(
            "[libp2p] tcp publisher={} subscriber={}",
            publisher.local_peer_id(),
            subscriber.local_peer_id()
        );
        publisher.behaviour_mut().gossipsub.subscribe(&topic)?;
        subscriber.behaviour_mut().gossipsub.subscribe(&topic)?;

        subscriber.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
        let subscriber_addr = wait_for_listen_addr(&mut subscriber, "subscriber", "/tcp/").await?;
        publisher.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
        let _ = wait_for_listen_addr(&mut publisher, "publisher", "/tcp/").await?;

        publisher.dial(subscriber_addr.clone())?;
        println!("[libp2p] dialling tcp addr {subscriber_addr}");

        let deadline = tokio::time::sleep(std::time::Duration::from_secs(30));
        tokio::pin!(deadline);
        let mut publisher_connected = false;
        let mut subscriber_connected = false;
        let mut message_seen = false;
        let mut published = false;
        let payload = b"libp2p network stack payload".to_vec();

        loop {
            tokio::select! {
                _ = &mut deadline => anyhow::bail!("timed out waiting for gossipsub message"),
                event = publisher.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] publisher connected to {peer_id}");
                        if peer_id == *subscriber.local_peer_id() {
                            publisher_connected = true;
                            publisher.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] publisher identify received {} listen addrs", info.listen_addrs.len());
                    }
                    _ => {}
                },
                event = subscriber.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[libp2p] subscriber connected to {peer_id}");
                        if peer_id == *publisher.local_peer_id() {
                            subscriber_connected = true;
                            subscriber.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        println!("[libp2p] subscriber identify received {} listen addrs", info.listen_addrs.len());
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message,
                        ..
                    })) => {
                        println!(
                            "[libp2p] subscriber got gossipsub message from {propagation_source} ({} bytes)",
                            message.data.len()
                        );
                        assert_eq!(propagation_source, *publisher.local_peer_id());
                        assert_eq!(message.data, payload);
                        message_seen = true;
                    }
                    _ => {}
                },
            }

            if publisher_connected && subscriber_connected && message_seen {
                break;
            }

            if publisher_connected && subscriber_connected && !published {
                match publisher
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), payload.clone())
                {
                    Ok(_) => {
                        println!("[libp2p] publisher sent gossipsub payload");
                        published = true;
                    }
                    Err(gossipsub::PublishError::InsufficientPeers) => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }

        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg_attr(
        not(feature = "relay_tests"),
        ignore = "expensive networking test; run with --features relay_tests --ignored"
    )]
    async fn libp2p_relay_gossipsub_roundtrip() -> anyhow::Result<()> {
        let _guard = network_lock().lock().await;
        let relay_candidates = relay_bootstrap_candidates()?;
        for relay_bootstrap in relay_candidates {
            println!("[libp2p] trying public relay bootstrap: {relay_bootstrap}");
            match run_relay_gossipsub_roundtrip_with_bootstrap(relay_bootstrap.clone()).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    println!(
                        "[libp2p] public relay bootstrap failed for {relay_bootstrap}: {err:#}"
                    );
                }
            }
        }

        println!("[libp2p] falling back to local relay");
        return run_relay_gossipsub_roundtrip_local().await;
    }
}
