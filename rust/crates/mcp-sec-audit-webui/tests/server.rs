//! Integration tests for the axum router (routes reachable, state wired).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use mcp_sec_audit_webui::state::RunManager;

#[tokio::test]
async fn index_serves_html() {
    let app = mcp_sec_audit_webui::server::build_router(RunManager::new());
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn import_valid_config_returns_ok() {
    let app = mcp_sec_audit_webui::server::build_router(RunManager::new());
    let body = "[scan]\ntargets = [\"src\"]\n";
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/import")
                .header("content-type", "text/plain")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
