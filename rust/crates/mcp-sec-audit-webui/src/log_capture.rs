//! A tracing Layer that captures every log line into the event stream as a
//! `Log` event, attributing each to its nearest `repo` span. This mirrors the
//! CLI's `ModuleFormat::repo_from_context`, self-contained because the webui
//! crate cannot depend on the cli crate (known v6 duplication).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mcp_sec_audit_core::LogLevel;
use mcp_sec_audit_core::events::AnalysisEvent;
use tracing::Event;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use crate::state::RunManager;

/// A [`tracing_subscriber::Layer`] that folds every log event into the
/// `RunManager` as an `AnalysisEvent::Log`, attributed to the nearest ancestor
/// span that carries a `repo` field.
pub struct CaptureLayer {
    manager: RunManager,
    /// span id -> recorded fields (populated in `on_new_span`).
    span_fields: Arc<Mutex<HashMap<Id, HashMap<String, String>>>>,
}

impl CaptureLayer {
    pub fn new(manager: RunManager) -> Self {
        Self {
            manager,
            span_fields: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S> Layer<S> for CaptureLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _ctx: Context<'_, S>) {
        let mut fields = HashMap::new();
        let mut v = SpanVisitor { fields: &mut fields };
        attrs.record(&mut v);
        self.span_fields.lock().unwrap().insert(id.clone(), fields);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut v = MsgVisitor::default();
        event.record(&mut v);

        let level = match *event.metadata().level() {
            tracing::Level::ERROR => LogLevel::Error,
            tracing::Level::WARN => LogLevel::Warn,
            tracing::Level::INFO => LogLevel::Info,
            tracing::Level::DEBUG => LogLevel::Debug,
            tracing::Level::TRACE => LogLevel::Trace,
        };

        // Nearest ancestor span that recorded a `repo` field.
        let repo = ctx
            .event_scope(event)
            .and_then(|scope| {
                let fields = self.span_fields.lock().unwrap();
                for span in scope {
                    let id = span.id();
                    if let Some(map) = fields.get(&id)
                        && let Some(repo) = map.get("repo")
                    {
                        return Some(repo.clone());
                    }
                }
                None
            })
            .unwrap_or_default();

        self.manager
            .record(AnalysisEvent::Log { repo, level, line: v.message });
    }
}

/// Records a span's fields into a `HashMap<String, String>`.
struct SpanVisitor<'a> {
    fields: &'a mut HashMap<String, String>,
}

impl Visit for SpanVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_string(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.insert(field.name().to_string(), value.to_string());
    }
}

/// Captures the `message` field of an event.
#[derive(Default)]
struct MsgVisitor {
    message: String,
}

impl Visit for MsgVisitor {
    // Interpolated messages (`info!("discovered {}", n)`) arrive as
    // `fmt::Arguments` via `record_debug`.
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }

    // Literal messages (`info!("rule analysis complete")`) arrive as `&str`
    // via `record_str`; without this arm they would be silently dropped.
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::RunSnapshot;
    use tracing_subscriber::layer::SubscriberExt;

    /// Run `body` under a default subscriber that routes through a fresh
    /// `CaptureLayer` backed by a fresh `RunManager`; return the manager's
    /// snapshot for assertion.
    fn capture_logs<F: FnOnce()>(body: F) -> RunSnapshot {
        let mgr = RunManager::new();
        let subscriber =
            tracing_subscriber::registry().with(CaptureLayer::new(mgr.clone()));
        tracing::subscriber::with_default(subscriber, body);
        mgr.snapshot()
    }

    #[test]
    fn captures_literal_message_via_record_str() {
        // `info!("hello")`: the `message` field is a `&str`, delivered via
        // `record_str`. Without that arm the message would be silently empty.
        let snap = capture_logs(|| tracing::info!("hello"));
        assert_eq!(snap.logs[""][0].1, "hello");
    }

    #[test]
    fn captures_interpolated_message_via_record_debug() {
        // `info!("discovered {}", n)`: the `message` field is `fmt::Arguments`,
        // delivered via `record_debug`.
        let snap = capture_logs(|| tracing::info!("discovered {}", 3));
        assert_eq!(snap.logs[""][0].1, "discovered 3");
    }

    #[test]
    fn attributes_repo_from_display_span_field() {
        // `repo = %name` is what the pipeline actually uses; `%` routes through
        // `SpanVisitor::record_debug` and formats the value to "excel".
        let snap = capture_logs(|| {
            tracing::info_span!("repo", repo = %"excel").in_scope(|| {
                tracing::info!("in excel repo");
            });
        });
        assert_eq!(snap.logs["excel"][0].1, "in excel repo");
    }

    #[test]
    fn attributes_repo_from_literal_span_field() {
        // A bare `repo = "excel"` string routes through `record_str`.
        let snap = capture_logs(|| {
            tracing::info_span!("repo", repo = "excel").in_scope(|| {
                tracing::info!("literal repo field");
            });
        });
        assert_eq!(snap.logs["excel"][0].1, "literal repo field");
    }

    #[test]
    fn level_maps_to_core_log_level() {
        let snap = capture_logs(|| tracing::warn!("careful"));
        assert_eq!(snap.logs[""][0].0, "warn");
    }

    #[test]
    fn empty_repo_when_no_repo_span() {
        let snap = capture_logs(|| tracing::info!("unscoped"));
        assert!(snap.logs.contains_key(""), "unscoped log should key on empty repo");
        assert_eq!(snap.logs[""][0].1, "unscoped");
    }
}
