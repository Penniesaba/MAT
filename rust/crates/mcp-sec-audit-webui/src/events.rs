//! WebSocket endpoint: replay snapshot then stream live AnalysisEvents.

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use tokio::sync::broadcast;

use crate::state::RunManager;

/// Axum handler: upgrade to a WebSocket and start serving events.
///
/// The first frame a client receives is a `{"type":"snapshot","data":…}`
/// envelope carrying the full current `RunSnapshot`; every subsequent frame is
/// a `{"type":"event","data":…}` envelope carrying one live `AnalysisEvent`
/// from `RunManager::subscribe()`.
pub async fn ws_handler(ws: WebSocketUpgrade, State(manager): State<RunManager>) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, manager))
}

async fn handle_socket(mut socket: WebSocket, manager: RunManager) {
    // 1. Send snapshot as the first frame (JSON envelope).
    let snapshot = serde_json::json!({
        "type": "snapshot",
        "data": manager.snapshot(),
    });
    if socket.send(Message::Text(snapshot.to_string().into())).await.is_err() {
        return;
    }

    // 2. Stream live events until the client closes the socket.
    let mut rx = manager.subscribe();
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Ok(ev) => {
                        let frame = serde_json::json!({ "type": "event", "data": ev });
                        if socket.send(Message::Text(frame.to_string().into())).await.is_err() {
                            return;
                        }
                    }
                    // A slow client fell behind; skip the missed events rather
                    // than dropping the connection (it still has the snapshot).
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    // The run ended and every sender dropped; nothing more to send.
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
            msg = socket.recv() => {
                // We don't act on inbound frames; keep serving until the client
                // closes (or the socket errors).
                match msg {
                    None | Some(Ok(Message::Close(_))) => return,
                    _ => {}
                }
            }
        }
    }
}
