pub mod message;
pub mod room;

pub use message::{IncomingMessage, Message};
pub use room::{CreateRoomResponse, Room, RoomConfig, RoomType};

/// PinChat wire-protocol version.
///
/// First explicit numbered version. Clients before this release are "v0 implicit"
/// (no `v` field in header, no `Sec-WebSocket-Protocol` subprotocol negotiation)
/// and will be rejected by the server.
pub const PINCHAT_PROTOCOL_VERSION: u8 = 1;
