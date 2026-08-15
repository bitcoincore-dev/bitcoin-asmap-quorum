//! CLI-level negative tests, one per defect.
//!
//! Python-free and in the default `cargo test` run, for the same reason as
//! `crates/asmap-codec/tests/negative_codec.rs`: these assert what the binary
//! must do, not what the oracle does. Parity with `asmap-tool.py` is covered by
//! `differential_python.rs`.
//!
//! Each test asserts the exit status, the stderr text, **and** the bytes of the
//! output file — the original defects all produced a plausible-looking exit
//! status with the wrong file on disk.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_bitcoin-asmap-quorum");

/// Vectors are shared with the codec crate's negative tests rather than
/// duplicated, so the two can never drift apart.
fn vector(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../asmap-codec/tests/vectors")
        .join(name)
}

/// A per-test scratch directory under `target/`, removed and recreated on entry
/// so a rerun never sees a previous run's output file.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp/cli-negative")
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

fn run(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "error")
        .output()
        .expect("spawn the asmap CLI")
}

fn cli(args: &[&str]) -> Output {
    let owned: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_ref()).collect();
    run(&owned)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn expect_failure(out: &Output, needle: &str) {
    assert!(
        !out.status.success(),
        "expected a non-zero exit; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        stderr(out)
    );
    let msg = stderr(out);
    assert!(
        msg.contains(needle),
        "stderr did not mention {needle:?}: {msg}"
    );
}

fn expect_success(out: &Output) {
    assert!(
        out.status.success(),
        "expected exit 0; stderr={:?}",
        stderr(out)
    );
}

// ---------------------------------------------------------------------------
// Defect 1 — `encode` of a malformed text file exited 0 and wrote a 0-byte map.
// ---------------------------------------------------------------------------

#[test]
fn cli_encode_malformed_text_exits_nonzero() {
    let scratch = Scratch::new("encode_malformed");
    let out_path = scratch.path("out.dat");
    let out = cli(&[
        "encode",
        vector("malformed.txt").to_str().unwrap(),
        out_path.to_str().unwrap(),
    ]);

    expect_failure(&out, "unparseable line 'this is garbage'");
    // The original bug's signature was rc=0 plus a zero-byte file. The load now
    // fails before the output is opened, so nothing is written at all.
    // (`asmap-tool.py` does leave a zero-byte file behind, because argparse
    // opens the output eagerly; not writing one is strictly safer and is not a
    // behavioural difference any consumer can depend on.)
    assert!(
        !out_path.exists(),
        "a failed encode must not leave an output file behind"
    );
}

#[test]
fn cli_encode_invalid_asn_exits_nonzero() {
    let scratch = Scratch::new("encode_bad_asn");
    let out_path = scratch.path("out.dat");
    let out = cli(&[
        "encode",
        vector("bad_asn.txt").to_str().unwrap(),
        out_path.to_str().unwrap(),
    ]);
    expect_failure(&out, "invalid ASN 'ASxyz'");
    assert!(!out_path.exists());
}

#[test]
fn cli_encode_valid_text_still_succeeds() {
    let scratch = Scratch::new("encode_good");
    let out_path = scratch.path("out.dat");
    let out = cli(&[
        "encode",
        vector("good.txt").to_str().unwrap(),
        out_path.to_str().unwrap(),
    ]);
    expect_success(&out);
    let bytes = std::fs::read(&out_path).expect("output written");
    assert!(
        !bytes.is_empty(),
        "a non-empty map must not encode to 0 bytes"
    );
}

// ---------------------------------------------------------------------------
// Defect 2 — non-canonical prefixes were silently reinterpreted.
// ---------------------------------------------------------------------------

#[test]
fn cli_encode_non_canonical_prefix_exits_nonzero() {
    let scratch = Scratch::new("encode_non_canonical");
    let out_path = scratch.path("out.dat");
    let out = cli(&[
        "encode",
        vector("non_canonical.txt").to_str().unwrap(),
        out_path.to_str().unwrap(),
    ]);
    expect_failure(&out, "invalid network '1.2.3.4/8'");
    assert!(!out_path.exists());

    // And specifically: it was *not* silently reinterpreted as `1.0.0.0/8`.
    let canonical = scratch.path("canonical.txt");
    std::fs::write(&canonical, "1.0.0.0/8 AS7\n").unwrap();
    let good_out = scratch.path("canonical.dat");
    expect_success(&cli(&[
        "encode",
        canonical.to_str().unwrap(),
        good_out.to_str().unwrap(),
    ]));
    assert!(
        std::fs::read(&good_out).unwrap() != Vec::<u8>::new(),
        "the canonical form must still encode"
    );
}

// ---------------------------------------------------------------------------
// Defect 3 — a three-byte valid binary map was rejected as "ambiguous".
// ---------------------------------------------------------------------------

#[test]
fn cli_decode_three_byte_map_succeeds() {
    let scratch = Scratch::new("decode_three_byte");
    let out_path = scratch.path("out.txt");
    let out = cli(&[
        "decode",
        vector("three_byte_utf8.bin").to_str().unwrap(),
        out_path.to_str().unwrap(),
    ]);

    let msg = stderr(&out);
    assert!(
        !msg.contains("is ambiguous"),
        "a valid three-byte map must not be called ambiguous: {msg}"
    );
    expect_success(&out);
    assert_eq!(
        std::fs::read_to_string(&out_path).expect("output written"),
        "8000::/1 AS6\n"
    );
}

/// The other side of the same fix: an input that really *is* ambiguous must
/// still be refused, with `asmap-tool.py`'s exact wording. The vector came out
/// of the differential's own random corpus, and the Python rejects it too.
#[test]
fn cli_decode_ambiguous_input_exits_nonzero() {
    let scratch = Scratch::new("decode_ambiguous");
    let out_path = scratch.path("out.txt");
    let out = cli(&[
        "decode",
        vector("ambiguous.bin").to_str().unwrap(),
        out_path.to_str().unwrap(),
    ]);
    expect_failure(&out, "is ambiguous.");
    assert!(!out_path.exists(), "nothing should be written");
}

// ---------------------------------------------------------------------------
// Defect 4 — `--fill` changed nothing.
// ---------------------------------------------------------------------------

#[test]
fn cli_decode_fill_changes_output() {
    let scratch = Scratch::new("decode_fill");
    let input = vector("fill_differs.bin");

    let mut seen: Vec<(bool, bool, String)> = Vec::new();
    for nonoverlapping in [false, true] {
        for fill in [false, true] {
            let out_path = scratch.path(&format!("out-{nonoverlapping}-{fill}.txt"));
            let mut args: Vec<&str> = vec!["decode"];
            if fill {
                args.push("--fill");
            }
            if nonoverlapping {
                args.push("-n");
            }
            args.push(input.to_str().unwrap());
            args.push(out_path.to_str().unwrap());
            expect_success(&cli(&args));
            seen.push((
                nonoverlapping,
                fill,
                std::fs::read_to_string(&out_path).expect("output written"),
            ));
        }
    }

    let get = |n: bool, f: bool| -> &str {
        &seen
            .iter()
            .find(|(sn, sf, _)| *sn == n && *sf == f)
            .expect("combination present")
            .2
    };

    // Reference output from the vendored asmap.py on the same vector.
    assert_eq!(
        get(true, false),
        "4000::/3 AS2\n6000::/5 AS1\n7000::/5 AS1\n8000::/2 AS2\nc000::/3 AS1\n"
    );
    assert_eq!(
        get(true, true),
        "4000::/3 AS2\n6000::/3 AS1\n8000::/2 AS2\nc000::/3 AS1\n"
    );
    assert_ne!(
        get(true, false),
        get(true, true),
        "--fill must change the non-overlapping output"
    );
    assert_ne!(
        get(false, false),
        get(false, true),
        "--fill must change the overlapping output"
    );
}

// ---------------------------------------------------------------------------
// Defect 5 — `decode` ignored `overlapping`, so the default never matched
// `asmap-tool.py`'s default.
// ---------------------------------------------------------------------------

#[test]
fn cli_decode_nonoverlapping_flag_changes_output() {
    let scratch = Scratch::new("decode_nonoverlapping");
    let input = vector("minimal_vs_flat.bin");

    let default_path = scratch.path("default.txt");
    expect_success(&cli(&[
        "decode",
        input.to_str().unwrap(),
        default_path.to_str().unwrap(),
    ]));
    let flat_path = scratch.path("flat.txt");
    expect_success(&cli(&[
        "decode",
        "-n",
        input.to_str().unwrap(),
        flat_path.to_str().unwrap(),
    ]));

    let default = std::fs::read_to_string(&default_path).unwrap();
    let flat = std::fs::read_to_string(&flat_path).unwrap();

    // Reference output from the vendored asmap.py. The default is the *minimal*
    // (overlapping) form, matching asmap-tool.py's default.
    assert_eq!(
        default,
        "::/2 AS2\n6000::/3 AS2\n8000::/1 AS3\ne000::/3 AS2\n"
    );
    assert_eq!(
        flat,
        "::/2 AS2\n6000::/3 AS2\n8000::/2 AS3\nc000::/3 AS3\ne000::/3 AS2\n"
    );
    assert_ne!(default, flat, "-n must change the output");
    assert!(
        default.lines().count() < flat.lines().count(),
        "the default must be the shorter, overlapping form"
    );
}

/// Whatever `decode` emits must re-`encode` to the same map — for every flag
/// combination that is lossless.
#[test]
fn cli_decode_output_re_encodes_to_the_same_map() {
    let scratch = Scratch::new("decode_reencode");
    for vec_name in [
        "minimal_vs_flat.bin",
        "fill_differs.bin",
        "three_byte_utf8.bin",
    ] {
        let input = vector(vec_name);
        let original = std::fs::read(&input).unwrap();
        for nonoverlapping in [false, true] {
            let txt = scratch.path(&format!("{vec_name}-{nonoverlapping}.txt"));
            let mut args: Vec<&str> = vec!["decode"];
            if nonoverlapping {
                args.push("-n");
            }
            args.push(input.to_str().unwrap());
            args.push(txt.to_str().unwrap());
            expect_success(&cli(&args));

            let back = scratch.path(&format!("{vec_name}-{nonoverlapping}.bin"));
            expect_success(&cli(&[
                "encode",
                txt.to_str().unwrap(),
                back.to_str().unwrap(),
            ]));
            assert_eq!(
                std::fs::read(&back).unwrap(),
                original,
                "{vec_name} nonoverlapping={nonoverlapping}: decode/encode is not a round-trip"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Claim validation (docs/CLAIM-VALIDATION.md) — the three reproduced defects,
// asserted at the CLI boundary an operator actually uses.
// ---------------------------------------------------------------------------

/// Builds one claim line with the `claim_hash` the engine will recompute.
///
/// Mirrors `canonical_claim_bytes`: entries sorted by `(ip_prefix, asn)` as
/// text, then `epoch=`/`sender=` headers and one `prefix|asn` line per entry.
fn claim_line(epoch: u64, sender_id: &str, entries: &[(&str, u32)]) -> String {
    use sha2::{Digest, Sha256};

    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(&b.1)));
    let mut canonical = format!("epoch={epoch}\nsender={sender_id}\n");
    for (prefix, asn) in &sorted {
        canonical.push_str(&format!("{prefix}|{asn}\n"));
    }
    let claim_hash = hex::encode(Sha256::digest(canonical.as_bytes()));
    let entries_json = entries
        .iter()
        .map(|(prefix, asn)| format!("{{\"ip_prefix\":\"{prefix}\",\"asn\":{asn}}}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"epoch\":{epoch},\"sender_id\":\"{sender_id}\",\"claim_hash\":\"{claim_hash}\",\"entries\":[{entries_json}]}}"
    )
}

/// A real base58 PeerId, since `sender_id` must parse as one.
fn peer_id() -> String {
    libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_string()
}

fn report_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).expect("report file")).expect("report json")
}

/// `1.2.3.0/24 AS4200000000` reaching quorum used to abort the process inside
/// the codec's `assert!(self.can_encode(val))`, in release builds too.
#[test]
fn cli_replay_rejects_out_of_cap_asn_instead_of_aborting() {
    let scratch = Scratch::new("replay_asn_cap");
    let claims = scratch.path("claims.jsonl");
    let map = scratch.path("out.map");
    let report = scratch.path("out.json");
    std::fs::write(
        &claims,
        claim_line(42, &peer_id(), &[("1.2.3.0/24", 4_200_000_000)]),
    )
    .unwrap();

    let out = cli(&[
        "replay",
        "-t",
        "1",
        "-e",
        "42",
        "--output",
        map.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        claims.to_str().unwrap(),
    ]);
    // Rejected rather than aborted — the point of this test — and now also
    // *reported* as a failure, because the only thing left to publish was an
    // empty map. The report is still written, so the reason survives the
    // non-zero exit and an operator can tell this from genuine disagreement.
    expect_failure(&out, "empty consensus map");
    assert!(
        stderr(&out).contains("asn_out_of_range=1"),
        "the failure must name the rejection reason: {}",
        stderr(&out)
    );

    let report_value = report_json(&report);
    assert_eq!(report_value["rejected_claims"]["asn_out_of_range"], 1);
    assert_eq!(report_value["accepted_claims"], 0);
    assert_eq!(report_value["entries"].as_array().map(Vec::len), Some(0));
}

/// A single default-route entry used to produce a map in which every address in
/// its family resolved to the claimant's ASN — and `verify` passed on it.
///
/// Both spellings are covered. `::/0` was rejected from the start; `0.0.0.0/0`
/// was waved through as "harmless because `ip_to_bits` still emits the 96 bits
/// of the mapped range", which is true of the trie root and false of the
/// consequence — those 96 bits *are* the whole of IPv4, and `decode` of the
/// resulting artifact printed exactly `0.0.0.0/0 AS666`.
#[test]
fn cli_replay_rejects_default_route_takeover() {
    for (spelling, tag) in [("::/0", "v6"), ("0.0.0.0/0", "v4")] {
        let scratch = Scratch::new(&format!("replay_default_route_{tag}"));
        let claims = scratch.path("claims.jsonl");
        let map = scratch.path("out.map");
        let report = scratch.path("out.json");
        std::fs::write(&claims, claim_line(42, &peer_id(), &[(spelling, 666)])).unwrap();

        let out = cli(&[
            "replay",
            "-t",
            "1",
            "-e",
            "42",
            "--output",
            map.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            claims.to_str().unwrap(),
        ]);
        expect_failure(&out, "empty consensus map");

        let report_value = report_json(&report);
        assert_eq!(
            report_value["rejected_claims"]["default_route_prefix"], 1,
            "{spelling} must be rejected as a default route"
        );
        assert_eq!(report_value["entries"].as_array().map(Vec::len), Some(0));

        let decoded = cli(&["decode", map.to_str().unwrap()]);
        expect_success(&decoded);
        assert!(
            !String::from_utf8_lossy(&decoded.stdout).contains("AS666"),
            "{spelling} must not reach the consensus map"
        );
    }
}

/// IPv6 text may not reach into the IPv4-mapped range from *above* it either.
///
/// `::/1` and `::ffff:0:0/95` (which host-masks to `::fffe:0:0/95`) are both
/// trie nodes strictly shallower than any dotted quad can express, and both
/// used to be accepted with an empty rejection ledger — reassigning every IPv4
/// address the map did not otherwise cover, without ever writing a `/0`.
#[test]
fn cli_replay_rejects_ipv6_prefixes_that_swallow_the_mapped_range() {
    for (spelling, tag) in [("::/1", "slash1"), ("::ffff:0:0/95", "slash95")] {
        let scratch = Scratch::new(&format!("replay_mapped_from_above_{tag}"));
        let claims = scratch.path("claims.jsonl");
        let map = scratch.path("out.map");
        let report = scratch.path("out.json");
        std::fs::write(&claims, claim_line(42, &peer_id(), &[(spelling, 666)])).unwrap();

        let out = cli(&[
            "replay",
            "-t",
            "1",
            "-e",
            "42",
            "--output",
            map.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            claims.to_str().unwrap(),
        ]);
        expect_failure(&out, "empty consensus map");

        let report_value = report_json(&report);
        assert_eq!(
            report_value["rejected_claims"]["ipv4_mapped_prefix"], 1,
            "{spelling} must be rejected as touching the IPv4-mapped range"
        );

        let decoded = cli(&["decode", map.to_str().unwrap()]);
        expect_success(&decoded);
        assert!(
            !String::from_utf8_lossy(&decoded.stdout).contains("AS666"),
            "{spelling} must not reach the consensus map"
        );
    }
}

/// The counterpart to the two tests above: the gates reject a *range*, not a
/// prefix length, so the shortest prefixes real snapshots contain still pass
/// end to end and still produce a map. `8000::/1` is one bit from `::/1` and
/// is accepted, because nothing distinguishes it from `224.0.0.0/3` — which
/// occurs in every snapshot under `data/`.
#[test]
fn cli_replay_still_accepts_the_shortest_real_world_prefixes() {
    let scratch = Scratch::new("replay_short_real_prefixes");
    let claims = scratch.path("claims.jsonl");
    let map = scratch.path("out.map");
    let report = scratch.path("out.json");
    std::fs::write(
        &claims,
        claim_line(
            42,
            &peer_id(),
            &[("224.0.0.0/3", 16509), ("1000::/4", 16509), ("8000::/1", 1)],
        ),
    )
    .unwrap();

    expect_success(&cli(&[
        "replay",
        "-t",
        "1",
        "-e",
        "42",
        "--output",
        map.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        claims.to_str().unwrap(),
    ]));

    let report_value = report_json(&report);
    assert!(
        report_value["rejected_claims"]
            .as_object()
            .is_some_and(serde_json::Map::is_empty),
        "no honest short prefix may be rejected: {}",
        report_value["rejected_claims"]
    );
    assert_eq!(report_value["entries"].as_array().map(Vec::len), Some(3));
    expect_success(&cli(&[
        "verify",
        report.to_str().unwrap(),
        map.to_str().unwrap(),
    ]));
}

/// `replay` must not seed its engine from attacker JSON.
///
/// With `--epoch` omitted the starting epoch came from `claims[0].epoch`, and
/// `QuorumEngine::with_limits` then widened `max_epoch` to accommodate it — so
/// a first record carrying `u64::MAX` pinned the engine there, every honest
/// claim behind it was rejected `stale_epoch`, and an empty artifact was
/// written with exit 0. Only the file order distinguished this from consensus.
#[test]
fn cli_replay_rejects_an_out_of_range_epoch_seeded_from_the_file() {
    let scratch = Scratch::new("replay_epoch_seed");
    let claims = scratch.path("claims.jsonl");
    let map = scratch.path("out.map");
    let report = scratch.path("out.json");
    let honest_a = peer_id();
    let honest_b = peer_id();
    std::fs::write(
        &claims,
        format!(
            "{}\n{}\n{}\n",
            claim_line(u64::MAX, &peer_id(), &[("10.0.0.0/8", 100)]),
            claim_line(1, &honest_a, &[("10.0.0.0/8", 100)]),
            claim_line(1, &honest_b, &[("10.0.0.0/8", 100)]),
        ),
    )
    .unwrap();

    expect_failure(
        &cli(&[
            "replay",
            "-t",
            "2",
            "--output",
            map.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            claims.to_str().unwrap(),
        ]),
        "above the absolute ceiling",
    );

    // The same three records with the hostile one last must still reach
    // consensus: the fix is a bound on the seed, not on file order.
    let reordered = scratch.path("reordered.jsonl");
    std::fs::write(
        &reordered,
        format!(
            "{}\n{}\n{}\n",
            claim_line(1, &honest_a, &[("10.0.0.0/8", 100)]),
            claim_line(1, &honest_b, &[("10.0.0.0/8", 100)]),
            claim_line(u64::MAX, &peer_id(), &[("10.0.0.0/8", 100)]),
        ),
    )
    .unwrap();
    let map_ok = scratch.path("ok.map");
    let report_ok = scratch.path("ok.json");
    expect_success(&cli(&[
        "replay",
        "-t",
        "2",
        "--output",
        map_ok.to_str().unwrap(),
        "--report",
        report_ok.to_str().unwrap(),
        reordered.to_str().unwrap(),
    ]));
    let report_value = report_json(&report_ok);
    assert_eq!(report_value["epoch"], 1);
    assert_eq!(report_value["accepted_claims"], 2);
    assert_eq!(report_value["rejected_claims"]["epoch_out_of_range"], 1);
    assert_eq!(report_value["entries"].as_array().map(Vec::len), Some(1));
}

/// `1.2.3.0/24` and `::ffff:1.2.3.0/120` are the same trie path but different
/// canonical strings, so one sender could vote a network twice and the output
/// depended on `HashMap` iteration order: ten identical replays used to produce
/// two different maps, and on most runs `verify` rejected the artifact the tool
/// had just written.
#[test]
fn cli_replay_of_ipv4_mapped_alias_is_rejected_and_deterministic() {
    let scratch = Scratch::new("replay_v4_mapped");
    let claims = scratch.path("claims.jsonl");
    let honest = peer_id();
    let aliaser = peer_id();
    std::fs::write(
        &claims,
        format!(
            "{}\n{}\n",
            claim_line(42, &honest, &[("1.2.3.0/24", 100)]),
            claim_line(
                42,
                &aliaser,
                &[("1.2.3.0/24", 100), ("::ffff:1.2.3.0/120", 200)]
            ),
        ),
    )
    .unwrap();

    let mut seen = std::collections::HashSet::new();
    for run in 0..10 {
        let map = scratch.path(&format!("out-{run}.map"));
        let report = scratch.path(&format!("out-{run}.json"));
        expect_success(&cli(&[
            "replay",
            "-t",
            "1",
            "-e",
            "42",
            "--output",
            map.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            claims.to_str().unwrap(),
        ]));
        // The tool must be able to verify what it just wrote, every time.
        expect_success(&cli(&[
            "verify",
            report.to_str().unwrap(),
            map.to_str().unwrap(),
        ]));
        let report_value = report_json(&report);
        assert_eq!(report_value["rejected_claims"]["ipv4_mapped_prefix"], 1);
        assert_eq!(report_value["accepted_claims"], 1);
        seen.insert(std::fs::read(&map).unwrap());
    }
    assert_eq!(seen.len(), 1, "replay output is not byte-reproducible");
}
