use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
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

fn write_snapshot(path: &Path, noisy: bool) {
    let mut body = String::from("1.2.3.0/24 AS64512\n2.3.4.0/24 AS64513\n");
    if noisy {
        body.push_str("3.4.5.0/24 AS64514\n");
    }
    fs::write(path, body).expect("snapshot write");
}

fn run_binary(args: &[String]) -> String {
    let output = Command::new(binary_path())
        .args(args)
        .output()
        .expect("binary execution");
    if !output.status.success() {
        panic!(
            "command failed: {:?}\nstdout:\n{}\nstderr:\n{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !stdout.is_empty() {
        println!("{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }
    stdout
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
    for idx in 0..node_count {
        let snapshot = temp_path(&format!("snapshot_{node_count}_{idx}"), "txt");
        write_snapshot(
            &snapshot,
            idx >= node_count.saturating_sub(node_count / 10).max(1),
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
    assert_eq!(report_value["entries"].as_array().map(|v| v.len()), Some(2));

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
fn consensus_lifecycle_25_nodes_cli() {
    lifecycle_for_nodes(25);
}

#[test]
fn consensus_lifecycle_50_nodes_cli() {
    lifecycle_for_nodes(50);
}

#[test]
fn consensus_lifecycle_100_nodes_cli() {
    lifecycle_for_nodes(100);
}
