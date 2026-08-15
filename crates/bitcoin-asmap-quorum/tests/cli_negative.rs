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
