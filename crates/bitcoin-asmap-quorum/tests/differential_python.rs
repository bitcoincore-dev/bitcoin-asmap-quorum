//! Differential test against the vendored `contrib/asmap/asmap.py`.
//!
//! Behind the off-by-default `python-differential` feature, so `cargo test` on
//! a clone without python3 still passes. **With** the feature on, a missing or
//! too-old interpreter is a hard failure — see `support/python.rs`.
//!
//! ## Why this is a Rust test driving python, and not the reverse
//!
//! The measurement that produced the original "encode 0/120, decode 81/120"
//! numbers was a standalone python script shelling out to the Rust binary. That
//! is the wrong direction for a permanent harness: it can only reach the CLI,
//! so it cannot compare library entry points such as `to_entries` or
//! `from_binary` acceptance directly; it cannot turn a Rust panic into a test
//! failure; it needs its own runner and exit-code convention; and it cannot be
//! selected with `cargo test`, so contributors never run it. Driving python
//! *from* Rust keeps one runner and one failure format, and reduces the python
//! side to a dumb oracle.
//!
//! ## Reproducing a failure
//!
//! One master seed, `ASMAP_TEST_SEED` (default 1234 — the value the original
//! measurement used). Trial *t* uses `splitmix64(master ^ t)` and seeds the
//! oracle's `random` with it immediately before `ASMap.from_random`, so a trial
//! is a pure function of its own index: widening `ASMAP_TEST_TRIALS` extends the
//! corpus without shifting it. `ASMAP_TEST_ONLY_TRIAL=<t>` replays exactly one.
//! Any divergence is dumped to `target/asmap-differential-failures/`.

#![cfg(feature = "python-differential")]

#[path = "support/python.rs"]
mod python;

use std::io::Cursor;
use std::path::{Path, PathBuf};

use asmap_codec::testgen::{RandomMapParams, SplitMix64, splitmix64};
use asmap_codec::{ASMap, bits_to_network, ip_to_bits, load_file, parse_network_prefix};
use python::{Oracle, from_hex, repo_root, run_asmap_tool, scratch_dir, to_hex};

const CLI: &str = env!("CARGO_BIN_EXE_bitcoin-asmap-quorum");

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .map(|v| {
            v.parse()
                .unwrap_or_else(|_| panic!("{key} must be a u64, got {v:?}"))
        })
        .unwrap_or(default)
}

fn master_seed() -> u64 {
    env_u64("ASMAP_TEST_SEED", 1234)
}

/// The trials this run covers. `ASMAP_TEST_ONLY_TRIAL` narrows it to one.
fn trial_indices(default_trials: u64) -> Vec<u64> {
    match std::env::var("ASMAP_TEST_ONLY_TRIAL") {
        Ok(v) => vec![v.parse().expect("ASMAP_TEST_ONLY_TRIAL must be a u64")],
        Err(_) => (0..env_u64("ASMAP_TEST_TRIALS", default_trials)).collect(),
    }
}

fn trial_seed(t: u64) -> u64 {
    splitmix64(master_seed() ^ t)
}

/// Parameters for trial `t`, drawn identically to the original measurement and
/// sent verbatim to the oracle so both sides build the same map.
fn trial_params(t: u64) -> (u64, RandomMapParams) {
    let seed = trial_seed(t);
    let mut rng = SplitMix64::new(seed);
    (seed, RandomMapParams::draw(&mut rng))
}

fn render(entries: &[(Vec<bool>, u32)]) -> Vec<String> {
    entries
        .iter()
        .map(|(prefix, asn)| format!("{} AS{asn}", bits_to_network(prefix)))
        .collect()
}

/// Rebuilds a map from rendered `NET ASn` lines, the way a consumer would.
fn rebuild(lines: &[String]) -> ASMap {
    let entries = lines
        .iter()
        .map(|line| {
            let (net, asn) = line
                .split_once(' ')
                .unwrap_or_else(|| panic!("bad line {line:?}"));
            let (ip, len) = parse_network_prefix(net).unwrap_or_else(|e| panic!("{line:?}: {e}"));
            let asn: u32 = asn
                .strip_prefix("AS")
                .unwrap_or_else(|| panic!("bad ASN in {line:?}"))
                .parse()
                .unwrap_or_else(|e| panic!("bad ASN in {line:?}: {e}"));
            (ip_to_bits(ip, len), asn)
        })
        .collect();
    let mut map = ASMap::new();
    map.update_multi(entries);
    map
}

fn load_text(text: &str) -> ASMap {
    load_file(
        Box::new(Cursor::new(text.as_bytes().to_vec())),
        "oracle-text",
    )
    .expect("the oracle's own canonical text form must load")
}

// ---------------------------------------------------------------------------
// Divergence bookkeeping
// ---------------------------------------------------------------------------

/// A divergence that is *not* a correctness failure: the two implementations
/// produced different but equally valid minimal entry lists.
///
/// `asmap.py`'s `_to_entries_minimal` picks among equally-short alternatives by
/// iterating `list(ret)` — CPython dict insertion order, which is inherited from
/// the iteration order of `set(left) | set(right)`, i.e. from set hash-table
/// layout. Its sibling `_to_binnode` uses an explicit `sorted(...)` in the same
/// place; the entries version does not. There is no deterministic Rust ordering
/// that reproduces CPython's, so this port fixes the order (ascending ASN, then
/// `None`) and treats an equal-length, semantically identical result as a tie
/// rather than a mismatch.
#[derive(Default)]
struct Tally {
    comparisons: u64,
    mismatches: u64,
    ties: u64,
    first_failures: Vec<String>,
}

impl Tally {
    fn record_equal(&mut self) {
        self.comparisons += 1;
    }

    fn record_tie(&mut self, detail: impl FnOnce() -> String) {
        self.comparisons += 1;
        self.ties += 1;
        if self.ties <= 3 {
            self.first_failures.push(format!("TIE {}", detail()));
        }
    }

    fn record_mismatch(&mut self, detail: impl FnOnce() -> String) {
        self.comparisons += 1;
        self.mismatches += 1;
        if self.mismatches <= 3 {
            self.first_failures.push(format!("MISMATCH {}", detail()));
        }
    }

    fn finish(&self, label: &str) {
        println!(
            "{label}: comparisons={} mismatches={} ties={}",
            self.comparisons, self.mismatches, self.ties
        );
        for line in &self.first_failures {
            println!("  {line}");
        }
        assert!(
            self.mismatches == 0,
            "{label}: {}/{} comparisons diverged from contrib/asmap/asmap.py",
            self.mismatches,
            self.comparisons
        );
    }
}

/// Writes everything needed to reproduce a divergence from the CI log alone.
fn dump_failure(trial: u64, tag: &str, map_bin: &[u8], text: &str, expected: &str, actual: &str) {
    let dir = repo_root()
        .join("target/asmap-differential-failures")
        .join(format!("trial-{trial}-{tag}"));
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let _ = std::fs::write(dir.join("map.bin"), map_bin);
    let _ = std::fs::write(dir.join("map.txt"), text);
    let _ = std::fs::write(dir.join("expected.txt"), expected);
    let _ = std::fs::write(dir.join("actual.txt"), actual);
    let _ = std::fs::write(
        dir.join("repro.sh"),
        format!(
            "#!/bin/sh\n# Replays exactly this trial.\nASMAP_TEST_SEED={} \
             ASMAP_TEST_ONLY_TRIAL={trial} \\\n  cargo test --features python-differential \
             -- --nocapture\n",
            master_seed()
        ),
    );
    eprintln!("divergence artifacts: {}", dir.display());
}

/// The first three differing lines, for an at-a-glance diff in the log.
fn first_diffs(expected: &[String], actual: &[String]) -> String {
    let mut out = Vec::new();
    for i in 0..expected.len().max(actual.len()) {
        let e = expected.get(i).map(String::as_str).unwrap_or("<missing>");
        let a = actual.get(i).map(String::as_str).unwrap_or("<missing>");
        if e != a {
            out.push(format!("line {i}: python={e:?} rust={a:?}"));
            if out.len() == 3 {
                break;
            }
        }
    }
    format!(
        "python={} lines, rust={} lines; {}",
        expected.len(),
        actual.len(),
        out.join("; ")
    )
}

fn write(path: &Path, contents: impl AsRef<[u8]>) {
    std::fs::write(path, contents).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
}

fn run_cli(cwd: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(CLI)
        .args(args)
        .current_dir(cwd)
        .env("RUST_LOG", "error")
        .output()
        .expect("spawn the asmap CLI")
}

// ---------------------------------------------------------------------------
// 1. encode — Rust `to_binary` and `encode` vs `ASMap.to_binary`
//
// This one is the regression guard: it reported 0 mismatches before any fix was
// applied and must never report anything else. Both sides start from the
// oracle's own canonical text form, so a broken decoder cannot mask a broken
// encoder.
// ---------------------------------------------------------------------------

#[test]
fn differential_encode_matches_python() {
    let mut oracle = Oracle::start("encode");
    let cwd = oracle.cwd.clone();
    let mut lib = Tally::default();
    let mut cli = Tally::default();

    for t in trial_indices(60) {
        let (seed, params) = trial_params(t);
        let sample = oracle.generate(
            seed,
            params.num_leaves,
            params.max_asn,
            params.unassigned_prob,
        );
        let text = sample.string("text");
        let in_path = cwd.join("in.txt");
        write(&in_path, &text);

        let map = load_text(&text);
        for fill in [false, true] {
            let expected = from_hex(sample.get("bin").get(if fill { "1" } else { "0" }).as_str());

            let actual = map.to_binary(fill);
            if actual == expected {
                lib.record_equal();
            } else {
                let (e, a) = (to_hex(&expected), to_hex(&actual));
                dump_failure(
                    t,
                    &format!("encode-lib-fill{}", u8::from(fill)),
                    &expected,
                    &text,
                    &e,
                    &a,
                );
                lib.record_mismatch(|| {
                    format!("trial {t} seed {seed} {params:?} fill={fill}: python={e} rust={a}")
                });
            }

            let out_path = cwd.join("out.bin");
            let _ = std::fs::remove_file(&out_path);
            let mut args: Vec<&str> = vec!["encode"];
            if fill {
                args.push("--fill");
            }
            args.push(in_path.to_str().unwrap());
            args.push(out_path.to_str().unwrap());
            let out = run_cli(&cwd, &args);
            assert!(
                out.status.success(),
                "trial {t}: `encode` failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let actual = std::fs::read(&out_path).expect("encode wrote its output");
            if actual == expected {
                cli.record_equal();
            } else {
                let (e, a) = (to_hex(&expected), to_hex(&actual));
                dump_failure(
                    t,
                    &format!("encode-cli-fill{}", u8::from(fill)),
                    &expected,
                    &text,
                    &e,
                    &a,
                );
                cli.record_mismatch(|| {
                    format!("trial {t} seed {seed} {params:?} fill={fill}: python={e} rust={a}")
                });
            }
        }
    }

    lib.finish("encode (library to_binary)");
    cli.finish("encode (CLI)");
}

// ---------------------------------------------------------------------------
// 2. decode — Rust `to_entries` vs `ASMap.to_entries`, all four flag combos.
//
// Reported 240/240 diverging before the `to_entries` rewrite (`overlapping` was
// ignored and `fill` was a no-op).
// ---------------------------------------------------------------------------

#[test]
fn differential_decode_matches_python() {
    let mut oracle = Oracle::start("decode");
    let mut tally = Tally::default();

    for t in trial_indices(60) {
        let (seed, params) = trial_params(t);
        let sample = oracle.generate(
            seed,
            params.num_leaves,
            params.max_asn,
            params.unassigned_prob,
        );
        let text = sample.string("text");
        let map = load_text(&text);
        let map_bin = from_hex(sample.get("bin").get("0").as_str());

        for overlapping in [false, true] {
            for fill in [false, true] {
                let key = format!("ov{}f{}", u8::from(overlapping), u8::from(fill));
                let expected = sample.get("entries").strings(&key);
                let actual = render(&map.to_entries(fill, overlapping));

                if expected == actual {
                    tally.record_equal();
                    continue;
                }

                // Equal length and the same reconstructed map means the two
                // picked different winners among equally-minimal alternatives.
                // See the `Tally` doc comment.
                let equivalent = expected.len() == actual.len()
                    && if fill {
                        rebuild(&expected).extends(&map) && rebuild(&actual).extends(&map)
                    } else {
                        rebuild(&expected) == rebuild(&actual) && rebuild(&actual) == map
                    };
                let detail = || {
                    format!(
                        "trial {t} seed {seed} {params:?} overlapping={overlapping} fill={fill}: {}",
                        first_diffs(&expected, &actual)
                    )
                };
                dump_failure(
                    t,
                    &format!("decode-{key}"),
                    &map_bin,
                    &text,
                    &expected.join("\n"),
                    &actual.join("\n"),
                );
                if equivalent {
                    tally.record_tie(detail);
                } else {
                    tally.record_mismatch(detail);
                }
            }
        }
    }

    tally.finish("decode (library to_entries)");
}

// ---------------------------------------------------------------------------
// 3. CLI decode vs `asmap-tool.py decode`, all four flag combinations.
//
// The only test that pays python process start-up per comparison, hence 20 maps
// rather than 60.
// ---------------------------------------------------------------------------

#[test]
fn differential_cli_matches_asmap_tool() {
    let mut oracle = Oracle::start("cli");
    let cwd = oracle.cwd.clone();
    let mut tally = Tally::default();

    for t in trial_indices(20) {
        let (seed, params) = trial_params(t);
        let sample = oracle.generate(
            seed,
            params.num_leaves,
            params.max_asn,
            params.unassigned_prob,
        );
        let map_bin = from_hex(sample.get("bin").get("0").as_str());
        let in_path = cwd.join("in.bin");
        write(&in_path, &map_bin);
        let source = load_text(&sample.string("text"));

        for nonoverlapping in [false, true] {
            for fill in [false, true] {
                let mut flags: Vec<&str> = Vec::new();
                if fill {
                    flags.push("-f");
                }
                if nonoverlapping {
                    flags.push("-n");
                }

                let py_path = cwd.join("py.txt");
                let _ = std::fs::remove_file(&py_path);
                let mut py_args = vec!["decode"];
                py_args.extend_from_slice(&flags);
                py_args.push(in_path.to_str().unwrap());
                py_args.push(py_path.to_str().unwrap());
                let py = run_asmap_tool(&cwd, &py_args);

                let rs_path = cwd.join("rs.txt");
                let _ = std::fs::remove_file(&rs_path);
                let mut rs_args = vec!["decode"];
                rs_args.extend_from_slice(&flags);
                rs_args.push(in_path.to_str().unwrap());
                rs_args.push(rs_path.to_str().unwrap());
                let rs = run_cli(&cwd, &rs_args);

                // Rejecting an input is a result too, and one the two must
                // agree on. Random corpora do throw up files that satisfy both
                // the binary and the text parser — trial 304 at
                // ASMAP_TEST_SEED=1234 is `237c0d001c0022` — and both
                // implementations must call those ambiguous rather than one
                // silently picking an interpretation.
                let py_err = String::from_utf8_lossy(&py.stderr).into_owned();
                let rs_err = String::from_utf8_lossy(&rs.stderr).into_owned();
                if py.status.success() != rs.status.success() {
                    tally.record_mismatch(|| {
                        format!(
                            "trial {t} seed {seed} {params:?} flags={flags:?}: python {} \
                             ({py_err:?}), rust {} ({rs_err:?})",
                            if py.status.success() {
                                "accepted"
                            } else {
                                "rejected"
                            },
                            if rs.status.success() {
                                "accepted"
                            } else {
                                "rejected"
                            },
                        )
                    });
                    continue;
                }
                if !py.status.success() {
                    // Both refused. The messages are byte-for-byte the same
                    // apart from the file name, which is identical here anyway.
                    if py_err.trim() == rs_err.trim() {
                        tally.record_equal();
                    } else {
                        tally.record_mismatch(|| {
                            format!(
                                "trial {t} seed {seed} {params:?} flags={flags:?}: both rejected \
                                 but python said {py_err:?} and rust said {rs_err:?}"
                            )
                        });
                    }
                    continue;
                }

                let expected: Vec<String> = std::fs::read_to_string(&py_path)
                    .expect("python output")
                    .lines()
                    .map(str::to_string)
                    .collect();
                let actual: Vec<String> = std::fs::read_to_string(&rs_path)
                    .expect("rust output")
                    .lines()
                    .map(str::to_string)
                    .collect();

                if expected == actual {
                    tally.record_equal();
                    continue;
                }
                let equivalent = expected.len() == actual.len()
                    && if fill {
                        rebuild(&expected).extends(&source) && rebuild(&actual).extends(&source)
                    } else {
                        rebuild(&expected) == rebuild(&actual) && rebuild(&actual) == source
                    };
                let detail = || {
                    format!(
                        "trial {t} seed {seed} {params:?} flags={flags:?}: {}",
                        first_diffs(&expected, &actual)
                    )
                };
                dump_failure(
                    t,
                    &format!("cli-{}{}", u8::from(nonoverlapping), u8::from(fill)),
                    &map_bin,
                    &sample.string("text"),
                    &expected.join("\n"),
                    &actual.join("\n"),
                );
                if equivalent {
                    tally.record_tie(detail);
                } else {
                    tally.record_mismatch(detail);
                }
            }
        }
    }

    tally.finish("cli decode vs asmap-tool.py");
}

// ---------------------------------------------------------------------------
// 4. `from_binary` acceptance parity, on valid encodings and on mutations of
//    them. A decoder that is more permissive than Bitcoin Core's is a consensus
//    hazard, and one that is stricter silently drops valid maps.
// ---------------------------------------------------------------------------

#[test]
fn differential_from_binary_matches_python() {
    let mut oracle = Oracle::start("from_binary");
    let mut tally = Tally::default();

    for t in trial_indices(60) {
        let (seed, params) = trial_params(t);
        let sample = oracle.generate(
            seed,
            params.num_leaves,
            params.max_asn,
            params.unassigned_prob,
        );
        let base = from_hex(sample.get("bin").get("0").as_str());

        // The valid encoding plus four deterministic mutations of it.
        let mut rng = SplitMix64::new(seed ^ 0x5EED_0FBA_D0DE_1234);
        let mut cases: Vec<(String, Vec<u8>)> = vec![("pristine".into(), base.clone())];
        {
            let mut truncated = base.clone();
            if !truncated.is_empty() {
                let keep = rng.below(truncated.len() as u64) as usize;
                truncated.truncate(keep);
            }
            cases.push(("truncated".into(), truncated));

            let mut flipped = base.clone();
            if !flipped.is_empty() {
                let i = rng.below(flipped.len() as u64) as usize;
                flipped[i] ^= 1u8 << rng.below(8);
            } else {
                flipped.push(0xff);
            }
            cases.push(("bitflip".into(), flipped));

            let mut extended = base.clone();
            extended.push(rng.below(256) as u8);
            cases.push(("appended".into(), extended));

            let mut padded = base.clone();
            padded.push(0);
            cases.push(("zero-padded".into(), padded));
        }

        for (tag, bytes) in cases {
            let hex = to_hex(&bytes);
            let py = oracle.decode_binary(&hex);
            let py_ok = py.get("ok").as_bool();
            let rust = ASMap::from_binary(&bytes);

            if py_ok != rust.is_some() {
                let detail = || {
                    format!(
                        "trial {t} seed {seed} {params:?} {tag}: python {} rust {} on {hex}",
                        if py_ok { "accepted" } else { "rejected" },
                        if rust.is_some() {
                            "accepted"
                        } else {
                            "rejected"
                        },
                    )
                };
                dump_failure(
                    t,
                    &format!("from_binary-{tag}"),
                    &bytes,
                    &sample.string("text"),
                    if py_ok { "accept" } else { "reject" },
                    if rust.is_some() { "accept" } else { "reject" },
                );
                tally.record_mismatch(detail);
                continue;
            }

            match rust {
                None => tally.record_equal(),
                Some(map) => {
                    let expected = py.strings("entries");
                    let actual = render(&map.to_entries(false, false));
                    if expected == actual {
                        tally.record_equal();
                    } else {
                        let detail = || {
                            format!(
                                "trial {t} seed {seed} {params:?} {tag} on {hex}: {}",
                                first_diffs(&expected, &actual)
                            )
                        };
                        dump_failure(
                            t,
                            &format!("from_binary-{tag}-entries"),
                            &bytes,
                            &sample.string("text"),
                            &expected.join("\n"),
                            &actual.join("\n"),
                        );
                        tally.record_mismatch(detail);
                    }
                }
            }
        }
    }

    tally.finish("from_binary acceptance and entries");
}

/// Belt and braces: the oracle and this crate must agree that the vendored
/// `asmap.py` is the file they think it is, and the scratch dirs must be under
/// `target/`.
#[test]
fn oracle_is_the_vendored_reference() {
    let pycache = repo_root().join("contrib/asmap/__pycache__");
    let pycache_existed = pycache.exists();

    let mut oracle = Oracle::start("preflight");
    let expected = repo_root().join("contrib/asmap/asmap.py");
    assert_eq!(
        PathBuf::from(&oracle.preflight.asmap_path)
            .canonicalize()
            .expect("oracle's asmap.py"),
        expected.canonicalize().expect("vendored asmap.py"),
        "the oracle imported an asmap.py that is not the vendored one"
    );

    // Exercise both child-process paths, then check that neither wrote next to
    // the sources: everything a test creates belongs under target/.
    let _ = oracle.decode_binary("130028");
    let _ = run_asmap_tool(&oracle.cwd, &["decode", "--help"]);
    assert!(scratch_dir("selftest").starts_with(repo_root().join("target")));
    assert!(
        pycache_existed || !pycache.exists(),
        "`-B` should have suppressed contrib/asmap/__pycache__, but a child process created it"
    );
}
