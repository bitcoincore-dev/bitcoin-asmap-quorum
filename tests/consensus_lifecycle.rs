use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

fn binary_path() -> PathBuf {
    std::env::var("CARGO_BIN_EXE_bitcoin-asmap-quorum")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_bitcoin_asmap_quorum"))
        .map(PathBuf::from)
        .expect("cargo did not expose the compiled binary path")
}

fn temp_path(stem: &str, ext: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("bitcoin_asmap_{stem}_{pid}_{nanos}.{ext}"))
}

fn real_ris_download_bottleneck_cli_rrc18() -> String {
    static TEMPLATE: OnceLock<String> = OnceLock::new();
    TEMPLATE
        .get_or_init(|| {
            println!("[integration] stage 0: prime real RRC18 bottleneck cache");
            let download_dir = temp_path("real_ris_download_18", "dir");
            let output_dir = temp_path("real_ris_bottleneck_18", "dir");
            fs::create_dir_all(&download_dir).expect("download dir");
            fs::create_dir_all(&output_dir).expect("output dir");

            run_binary(&[
                "download".to_string(),
                "-n".to_string(),
                "18".to_string(),
                "-o".to_string(),
                download_dir.to_string_lossy().into_owned(),
            ]);
            run_binary(&[
                "find-bottleneck".to_string(),
                "-d".to_string(),
                download_dir.to_string_lossy().into_owned(),
                "-o".to_string(),
                output_dir.to_string_lossy().into_owned(),
            ]);

            let mut bottleneck_files = fs::read_dir(&output_dir)
                .expect("bottleneck output dir")
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .collect::<Vec<_>>();
            bottleneck_files.sort();
            let bottleneck = fs::read_to_string(&bottleneck_files[0]).expect("bottleneck text");
            println!(
                "[integration] cached real RRC18 bottleneck with {} line(s)",
                bottleneck.lines().count()
            );

            let _ = fs::remove_dir_all(download_dir);
            let _ = fs::remove_dir_all(output_dir);

            bottleneck
        })
        .clone()
}

fn run_binary(args: &[String]) -> String {
    let status = Command::new(binary_path())
        .args(args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("binary execution");
    if !status.success() {
        panic!("command failed: {:?}", args);
    }
    String::new()
}

fn lifecycle_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lifecycle_for_nodes(node_count: usize) {
    let _guard = lifecycle_lock().lock().expect("lifecycle lock");
    let claims = temp_path(&format!("claims_{node_count}"), "json");
    let map = temp_path(&format!("consensus_{node_count}"), "map");
    let report = temp_path(&format!("consensus_{node_count}"), "json");
    let mut snapshots = Vec::new();

    println!("[integration] stage 1: materialize {node_count} developer snapshots");
    let base_snapshot = real_ris_download_bottleneck_cli_rrc18()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(2)
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    for idx in 0..node_count {
        let snapshot = temp_path(&format!("snapshot_{node_count}_{idx}"), "txt");
        let mut body = base_snapshot.clone();
        if idx >= node_count.saturating_sub(node_count / 10).max(1) {
            body.push_str("203.0.113.0/24 AS64514\n");
        }
        fs::write(&snapshot, body).expect("snapshot write");
        println!(
            "[integration] peer {}/{} snapshot ready: {}",
            idx + 1,
            node_count,
            snapshot.display()
        );
        snapshots.push(snapshot);
    }

    println!("[integration] stage 2: run CLI import across {node_count} peers");
    let mut import_args = vec![
        "import".to_string(),
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
    run_binary(&import_args);

    let claims_json = fs::read_to_string(&claims).expect("claims output");
    let claims_value: Value = serde_json::from_str(&claims_json).expect("claims json");
    assert_eq!(claims_value.as_array().map(|v| v.len()), Some(node_count));
    println!(
        "[integration] {} peers imported into claims batch",
        claims_value.as_array().map(|v| v.len()).unwrap_or(0)
    );

    println!("[integration] stage 3: run CLI replay into consensus artifact");
    let threshold = (node_count * 67).div_ceil(100);
    run_binary(&[
        "replay".to_string(),
        "-t".to_string(),
        threshold.to_string(),
        "-e".to_string(),
        "42".to_string(),
        "--topic".to_string(),
        "workflow".to_string(),
        "--output".to_string(),
        map.to_string_lossy().into_owned(),
        "--report".to_string(),
        report.to_string_lossy().into_owned(),
        claims.to_string_lossy().into_owned(),
    ]);

    let report_json = fs::read_to_string(&report).expect("report output");
    let report_value: Value = serde_json::from_str(&report_json).expect("report json");
    assert_eq!(report_value["threshold"].as_u64(), Some(threshold as u64));
    assert_eq!(
        report_value["accepted_claims"].as_u64(),
        Some(node_count as u64)
    );
    assert_eq!(
        report_value["participants"].as_array().map(|v| v.len()),
        Some(node_count)
    );
    assert!(
        report_value["entries"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    );
    println!(
        "[integration] consensus reached with {} participants and {} accepted claims",
        report_value["participants"]
            .as_array()
            .map(|v| v.len())
            .unwrap_or(0),
        report_value["accepted_claims"].as_u64().unwrap_or(0)
    );

    println!("[integration] stage 4: verify the emitted consensus report");
    run_binary(&[
        "verify".to_string(),
        report.to_string_lossy().into_owned(),
        map.to_string_lossy().into_owned(),
    ]);
    println!("[integration] verification complete");

    for snapshot in snapshots {
        let _ = fs::remove_file(snapshot);
    }
    let _ = fs::remove_file(claims);
    let _ = fs::remove_file(map);
    let _ = fs::remove_file(report);
}

#[test]
fn bitcoin_core_asmap_fixture_cli_roundtrip() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = repo_root.join("bitcoin/src/test/data/asmap.raw");
    assert!(fixture.exists(), "missing Bitcoin Core ASMap fixture");

    let decoded = temp_path("bitcoin_core_asmap_decoded", "txt");
    let claims = temp_path("bitcoin_core_asmap_claims", "json");
    let map = temp_path("bitcoin_core_asmap_consensus", "map");
    let report = temp_path("bitcoin_core_asmap_consensus", "json");

    println!("[integration] real fixture: decode Bitcoin Core asmap.raw");
    run_binary(&[
        "decode".to_string(),
        fixture.to_string_lossy().into_owned(),
        decoded.to_string_lossy().into_owned(),
    ]);

    let decoded_text = fs::read_to_string(&decoded).expect("decoded fixture");
    assert!(
        decoded_text.lines().any(|line| line.contains("AS")),
        "decoded fixture should contain AS mappings"
    );

    println!("[integration] real fixture: import decoded Bitcoin Core ASMap");
    run_binary(&[
        "import".to_string(),
        "-e".to_string(),
        "99".to_string(),
        "--sender-prefix".to_string(),
        "bitcoin-core".to_string(),
        "-o".to_string(),
        claims.to_string_lossy().into_owned(),
        decoded.to_string_lossy().into_owned(),
    ]);

    println!("[integration] real fixture: replay and verify");
    run_binary(&[
        "replay".to_string(),
        "-t".to_string(),
        "1".to_string(),
        "-e".to_string(),
        "99".to_string(),
        "--topic".to_string(),
        "bitcoin-core-fixture".to_string(),
        "--output".to_string(),
        map.to_string_lossy().into_owned(),
        "--report".to_string(),
        report.to_string_lossy().into_owned(),
        claims.to_string_lossy().into_owned(),
    ]);

    run_binary(&[
        "verify".to_string(),
        report.to_string_lossy().into_owned(),
        map.to_string_lossy().into_owned(),
    ]);

    let report_json = fs::read_to_string(&report).expect("report output");
    let report_value: Value = serde_json::from_str(&report_json).expect("report json");
    assert_eq!(report_value["accepted_claims"].as_u64(), Some(1));
    assert_eq!(
        report_value["participants"].as_array().map(|v| v.len()),
        Some(1)
    );
    assert!(
        report_value["entries"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    );

    let _ = fs::remove_file(decoded);
    let _ = fs::remove_file(claims);
    let _ = fs::remove_file(map);
    let _ = fs::remove_file(report);
}

fn ris_download_bottleneck(collector: u32) -> String {
    let download_dir = temp_path(&format!("real_ris_download_{collector}"), "dir");
    let output_dir = temp_path(&format!("real_ris_bottleneck_{collector}"), "dir");
    fs::create_dir_all(&download_dir).expect("download dir");
    fs::create_dir_all(&output_dir).expect("output dir");

    println!("[integration] stage 1: download a real RIPE RIS dump from rrc{collector:02}");
    run_binary(&[
        "download".to_string(),
        "-n".to_string(),
        collector.to_string(),
        "-o".to_string(),
        download_dir.to_string_lossy().into_owned(),
    ]);

    let mut downloaded = fs::read_dir(&download_dir)
        .expect("downloaded dir")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect::<Vec<_>>();
    downloaded.sort();
    assert!(!downloaded.is_empty(), "no MRT dump was downloaded");
    println!("[integration] downloaded {}", downloaded[0].display());

    println!("[integration] stage 2: extract bottlenecks from the real dump");
    run_binary(&[
        "find-bottleneck".to_string(),
        "-d".to_string(),
        download_dir.to_string_lossy().into_owned(),
        "-o".to_string(),
        output_dir.to_string_lossy().into_owned(),
    ]);

    let mut bottleneck_files = fs::read_dir(&output_dir)
        .expect("bottleneck output dir")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect::<Vec<_>>();
    bottleneck_files.sort();
    assert!(
        !bottleneck_files.is_empty(),
        "no bottleneck output produced"
    );

    let bottleneck = fs::read_to_string(&bottleneck_files[0]).expect("bottleneck text");
    println!("[integration] bottleneck report:\n{bottleneck}");
    assert!(bottleneck.lines().count() > 0);
    assert!(bottleneck.contains(" AS"));

    let _ = fs::remove_dir_all(download_dir);
    let _ = fs::remove_dir_all(output_dir);

    bottleneck
}

#[test]
#[cfg_attr(not(feature = "flaky_tests"), ignore)]
fn real_ris_download_bottleneck_cli_rrc18_smoke() {
    let bottleneck = ris_download_bottleneck(18);
    assert!(bottleneck.lines().count() > 0);
}

#[test]
#[cfg_attr(not(feature = "flaky_tests"), ignore = "downloads the ~400MB rrc00 dump; run with --ignored")]
fn real_ris_download_bottleneck_cli() {
    let bottleneck = ris_download_bottleneck(0);
    assert!(bottleneck.lines().count() > 0);
}
#[test]
#[ignore = "expensive integration test; run with --ignored"]
fn consensus_lifecycle_1_nodes_cli() {
    lifecycle_for_nodes(1);
}
#[test]
#[ignore = "expensive integration test; run with --ignored"]
fn consensus_lifecycle_2_nodes_cli() {
    lifecycle_for_nodes(2);
}

#[test]
#[ignore = "expensive integration test; run with --ignored"]
fn consensus_lifecycle_25_nodes_cli() {
    lifecycle_for_nodes(25);
}

#[test]
#[ignore = "expensive integration test; run with --ignored"]
fn consensus_lifecycle_50_nodes_cli() {
    lifecycle_for_nodes(50);
}

#[test]
#[ignore = "expensive integration test; run with --ignored"]
fn consensus_lifecycle_100_nodes_cli() {
    lifecycle_for_nodes(100);
}
