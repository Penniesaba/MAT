//! axum HTTP server + router for the web UI.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};

use crate::events;
use crate::run;
use crate::state::RunManager;
use crate::toml_import::{ConfigKind, parse_config, render_config};

/// Shared application state: the run manager (broadcast/events/cancel) plus the
/// currently loaded config (imported TOML), if any.
#[derive(Clone)]
pub struct AppState {
    manager: RunManager,
    config: Arc<Mutex<Option<ConfigKind>>>,
}

/// Let `State<RunManager>` extract the manager out of an `AppState`-state
/// router. `RunManager` is a local type, so the orphan rule is satisfied.
impl axum::extract::FromRef<AppState> for RunManager {
    fn from_ref(state: &AppState) -> RunManager {
        state.manager.clone()
    }
}

/// Build the axum router, wiring every route with the shared [`AppState`].
///
/// Takes the [`RunManager`] so the caller (the `serve` entry point) can install
/// a [`crate::log_capture::CaptureLayer`] over the *same* manager the WS
/// endpoint streams from — the two must share state for per-repo log lines to
/// fold into the event stream.
pub fn build_router(manager: RunManager) -> Router {
    let state = AppState {
        manager,
        config: Arc::new(Mutex::new(None)),
    };

    Router::new()
        .route("/", get(index))
        .route("/static/app.css", get(app_css))
        .route("/static/app.js", get(app_js))
        .route("/api/config", get(get_config).put(put_config))
        .route("/api/import", post(import))
        .route("/api/config/export", get(export))
        .route("/api/run", post(api_run))
        .route("/api/run/cancel", post(cancel))
        .route("/ws/events", get(events::ws_handler))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn app_css() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css")],
        include_str!("../static/app.css"),
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript")],
        include_str!("../static/app.js"),
    )
}

async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.config.lock().expect("config mutex");
    match cfg.as_ref() {
        Some(c) => match serde_json::to_string(c) {
            Ok(s) => (StatusCode::OK, s),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to serialize config: {e}"),
            ),
        },
        None => (StatusCode::OK, "null".to_string()),
    }
}

async fn put_config(State(state): State<AppState>, body: String) -> impl IntoResponse {
    match parse_config(&body) {
        Ok(c) => {
            *state.config.lock().expect("config mutex") = Some(c);
            (StatusCode::OK, "ok".to_string())
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("invalid config: {e:#}")),
    }
}

async fn import(State(state): State<AppState>, body: String) -> impl IntoResponse {
    match parse_config(&body) {
        Ok(c) => {
            // Bind the mutex guard once (the brief locked twice) and render from
            // the stored config.
            let mut guard = state.config.lock().expect("config mutex");
            *guard = Some(c);
            let rendered = render_config(guard.as_ref().expect("just stored")).unwrap_or_default();
            (StatusCode::OK, rendered)
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("invalid config: {e:#}")),
    }
}

async fn export(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.config.lock().expect("config mutex");
    match cfg.as_ref() {
        Some(c) => (StatusCode::OK, render_config(c).unwrap_or_default()),
        None => (StatusCode::NOT_FOUND, "no config loaded".to_string()),
    }
}

async fn api_run(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.config.lock().expect("config mutex").clone();
    match cfg {
        Some(ConfigKind::Batch(b)) => {
            if b.batch.repos.is_empty() {
                return (StatusCode::BAD_REQUEST, "batch config has no repos".to_string());
            }
            let _ = run::start_batch(state.manager.clone(), b);
            (StatusCode::ACCEPTED, "started batch".to_string())
        }
        Some(ConfigKind::Single(r)) => {
            let _ = run::start_single(state.manager.clone(), r);
            (StatusCode::ACCEPTED, "started single".to_string())
        }
        None => (StatusCode::BAD_REQUEST, "no config loaded".to_string()),
    }
}

async fn cancel(State(state): State<AppState>) -> impl IntoResponse {
    state.manager.cancel_token().cancel();
    (StatusCode::OK, "cancel requested".to_string())
}
