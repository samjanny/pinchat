//! Echo server for the Autobahn test suite (see README.md next to this
//! file). It runs the relay's own WebSocket transport, compiled in from
//! src/ws_transport.rs as it is, with the relay's limits and budgets, and
//! handles each connection the way the relay does:
//!
//! * a text message is sent back as it came;
//! * a ping is answered with a pong carrying its payload;
//! * a binary message is read and dropped, as the relay drops it, so the
//!   cases that expect binary echoes report a failure by design;
//! * the connection ends with the closing handshake of
//!   `ws_transport::close`, with the code the relay would use.

#[allow(dead_code)]
#[path = "../../../src/ws_transport.rs"]
mod ws_transport;

use axum::{Router, response::Response, routing::get};
use std::time::Duration;
use ws_transport::{
    Closing, InboundBudget, InboundTier, Incoming, Outgoing, WsSocket, WsUpgrade, close,
};

/// What the relay accepts as one message with `MAX_IMAGE_SIZE=2MB`, the
/// production setting (`max_ws_size` in src/handlers/websocket.rs).
const LIMIT: usize = 5_594_460;
/// The relay's idle timeout and message deadline, and its closing time.
const IDLE: Duration = Duration::from_secs(90);
const CLOSING: Duration = Duration::from_secs(5);

async fn echo(socket: WsSocket) {
    let (mut writer, mut reader) = socket.split();
    let closing = loop {
        let sent = match reader.next_within(IDLE).await {
            Some(Ok(Incoming::Text(text))) => writer.send(Outgoing::Text(&text)).await,
            Some(Ok(Incoming::Ping(payload))) => writer.send(Outgoing::Pong(&payload)).await,
            Some(Ok(Incoming::Pong | Incoming::Binary)) => Ok(()),
            Some(Ok(Incoming::Close(code))) => break Closing::Answer(code),
            Some(Err(error)) => break error.closing(),
            None => break Closing::Abort,
        };
        if sent.is_err() {
            break Closing::Abort;
        }
    };
    close(&mut writer, &mut reader, closing, CLOSING).await;
}

#[tokio::main]
async fn main() {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9001".to_string());
    // The relay's global tiers (src/state/app_state.rs). Autobahn connects
    // from one address, so the per-address tiers would only make it slower.
    let small = InboundTier::new(16 * 1024 * 1024);
    let large = InboundTier::new(64 * 1024 * 1024);
    let upgrade = move |ws: WsUpgrade| {
        let budget = InboundBudget::new(vec![small.clone()], vec![large.clone()]);
        async move { ws.on_upgrade("pinchat.v1", LIMIT, budget, echo) as Response }
    };
    let listener = tokio::net::TcpListener::bind(&address).await.unwrap();
    eprintln!("listening on {address}");
    axum::serve(listener, Router::new().route("/", get(upgrade)))
        .await
        .unwrap();
}
