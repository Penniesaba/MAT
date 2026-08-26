//! End-to-end smoke: a tiny vulnerable Python repo through `run_bench`.

use std::path::PathBuf;

use mcp_sec_audit_core::{run_bench, BenchOptions};
use tokio_util::sync::CancellationToken;

fn tiny_repo(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("app.py"), "import subprocess\nsubprocess.run(['ls'])\n").unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bench_runs_over_a_tiny_repo_and_writes_metrics() {
    let root = std::env::temp_dir().join(format!("mcp-bench-smoke-{}", std::process::id()));
    let corpus = root.join("corpus").join("tiny");
    tiny_repo(&corpus);
    let manifest_path = root.join("manifest.toml");
    let gt_path = root.join("ground-truth.toml");
    std::fs::write(
        &manifest_path,
        r#"
[scan]
exclude = ["__pycache__", ".venv", "node_modules", "target", ".git"]
[static]
enabled = true
[static.rule]
enabled = false
[static.taint]
enabled = true
forward = true
backward = true
max_depth = 8
entrypoint_required = false
[static.agent]
enabled = false
[static.codeql]
enabled = false
[fusion]
enabled = false
[[repo]]
slug = "tiny"
url = "git@github.com:example/tiny.git"
commit = "deadbeef"
language = "python"
evidence_tier = "cve"
vulns = ["CVE-tiny"]
"#,
    )
    .unwrap();
    std::fs::write(
        &gt_path,
        r#"
[vulns."CVE-tiny"]
repo_slug = "tiny"
language = "python"
cwe = "CWE-78"
category = "command_execution"
severity = "high"
evidence_tier = "cve"
sink_line = 2
sink_file = "app.py"
"#,
    )
    .unwrap();

    let metrics = run_bench(&manifest_path, &BenchOptions { tolerance: 5, max_parallel: 1 }, CancellationToken::new())
        .await
        .expect("bench");

    // This is a *plumbing* smoke test, not a detection test: it asserts the
    // bench path runs end-to-end and writes metrics; the scorer's hit/FP logic
    // is covered by the bench::scorer unit tests. `tp` is not asserted here
    // because whether the taint line flags the bare `subprocess.run` depends
    // on the built-in catalog, which this test does not assume.
    assert_eq!(metrics.repos.len(), 1);
    assert_eq!(metrics.overall.ground_truth, 1);

    let out_dir = manifest_path
        .parent()
        .unwrap()
        .join("bench_results");
    let metrics_files: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .unwrap()
        .flat_map(|e| e)
        .flat_map(|e| std::fs::read_dir(e.path()).ok())
        .flatten()
        .flat_map(|e| e)
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()) == Some("metrics.json"))
        .collect();
    assert_eq!(metrics_files.len(), 1);
}
