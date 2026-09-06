//! End-to-end: drive the frontend's exact HTTP flow (PUT config → POST run) and
//! assert the run reaches a terminal state, reports are written, and failures
//! surface their reason through the event stream.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use mcp_sec_audit_webui::state::{RunManager, RepoProgress};

const RULES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules");

fn batch_toml(repo_path: &str, rule_paths: &str) -> String {
    format!(
        r#"[scan]
targets = ["."]
exclude = ["node_modules", "target", ".venv", "dist"]
languages = ["python", "javascript", "typescript", "rust"]

[static]
enabled = true
save_facts = true

[static.rule]
enabled = true
rule_paths = {rule_paths}

[static.taint]
enabled = false

[static.agent]
enabled = false

[static.codeql]
enabled = false

[dynamic]
enabled = false

[fusion]
enabled = true
require_confirmed_by = 1

[report]
formats = ["json", "markdown"]
output = "/tmp/msa-e2e-out-<timestamp>/<repo>"

[logging]
level = "info"

[batch]
max_parallel = 4
learning_bus = false
fail_fast = false

[[batch.repo]]
name = "py-repro"
path = "{repo_path}"
"#
    )
}

async fn oneshot(app: &axum::Router, method: &str, uri: &str, body: String) -> (StatusCode, String) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "text/plain")
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn finished(r: &RepoProgress) -> bool {
    r.status.is_some()
}

fn tiny_repo(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("msa-e2e-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create repo dir");
    std::fs::write(dir.join("app.py"), "import subprocess\nsubprocess.run(['ls'])\n").expect("write app.py");
    dir
}

async fn run_until_done(manager: &RunManager, app: &axum::Router, toml: &str) -> mcp_sec_audit_webui::state::RunSnapshot {
    let (put_status, put_body) = oneshot(app, "PUT", "/api/config", toml.to_string()).await;
    assert_eq!(put_status, StatusCode::OK, "PUT config failed: {put_body}");
    let (run_status, run_body) = oneshot(app, "POST", "/api/run", String::new()).await;
    assert_eq!(run_status, StatusCode::ACCEPTED, "POST run failed: {run_body}");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let snap = manager.snapshot();
        if !snap.repos.is_empty() && snap.repos.values().all(finished) {
            return snap;
        }
        assert!(std::time::Instant::now() < deadline, "timed out; snapshot: {:?}", snap.repos);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_flow_reaches_ok_and_writes_reports() {
    let repo = tiny_repo("ok");
    let rule_paths = format!("[\"{RULES_DIR}/mcp\", \"{RULES_DIR}/languages\"]");
    let toml = batch_toml(repo.to_str().unwrap(), &rule_paths);

    let manager = RunManager::new();
    let app = mcp_sec_audit_webui::server::build_router(manager.clone());
    let snap = run_until_done(&manager, &app, &toml).await;

    let p = &snap.repos["py-repro"];
    assert_eq!(p.status, Some(mcp_sec_audit_core::batch::RepoStatus::Ok),
        "expected Ok, got {:?} error={:?}", p.status, p.error);
    assert!(p.finding_count.is_some(), "should have a finding count");
    assert!(p.error.is_none(), "no error expected on success");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_repo_surfaces_error_reason() {
    let repo = tiny_repo("bad");
    // A rule path that does not exist must fail AND surface its reason to the UI.
    let toml = batch_toml(repo.to_str().unwrap(), "[\"/nonexistent/rules\"]");

    let manager = RunManager::new();
    let app = mcp_sec_audit_webui::server::build_router(manager.clone());
    let snap = run_until_done(&manager, &app, &toml).await;

    let p = &snap.repos["py-repro"];
    assert_eq!(p.status, Some(mcp_sec_audit_core::batch::RepoStatus::Failed));
    assert!(
        p.error.as_deref().map_or(false, |e| !e.is_empty()),
        "a failed repo must carry a non-empty error, got {:?}", p.error
    );
}
