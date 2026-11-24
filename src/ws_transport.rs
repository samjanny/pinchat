//! Server side of the WebSocket protocol (RFC 6455), written for a relay.
//!
//! The relay used to speak WebSocket through a general-purpose library. That
//! library keeps, for every connection, one buffer for reading and one for
//! writing, grows each to the largest frame it has carried and never gives
//! the memory back while the connection lives. A room in which one image had
//! been exchanged therefore held several megabytes per participant until
//! everybody left, and a broadcast to N receivers copied the frame N times
//! on top of that. Newer releases of the library behave the same way.
//!
//! This module keeps nothing of the kind:
//!
//! * Reading. A fixed 4 KiB buffer holds frame headers and small frames. The
//!   payload of a text message is read straight into the allocation that
//!   becomes the `String` handed to the caller, so when the caller drops the
//!   message the connection holds nothing of it. That allocation grows with
//!   the bytes that actually arrive, not with the length a frame announces.
//! * Writing. A frame is a header of at most ten bytes followed by the
//!   payload, written from the caller's slice. A broadcast frame shared by
//!   twenty receivers is written twenty times from the same allocation and
//!   copied zero times; a receiver that does not read holds a reference to
//!   that allocation, not a copy of it.
//!
//! What is implemented is what a browser and this relay exchange: unextended
//! frames, text messages (fragmented or not), ping, pong and close, with the
//! closing handshake of section 7 of the RFC ([`close`]). Binary messages are
//! read and discarded without being stored, because the relay has no use for
//! them. No extension is negotiated, so the reserved bits of every frame must
//! be zero.
//!
//! Every message that needs more memory than a small fixed allowance takes
//! that memory from an [`InboundBudget`] shared by all connections before its
//! body is read, and a message has a deadline that control frames sent in
//! the middle of it do not move ([`WsReader::next_within`]). Together they
//! bound what peers can make the relay hold for messages they never finish.

use axum::{
    body::Body,
    extract::FromRequestParts,
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version,
        header::{
            CONNECTION, HOST, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
            SEC_WEBSOCKET_VERSION, UPGRADE,
        },
        request::Parts,
    },
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha1::{Digest, Sha1};
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

/// Largest payload of a control frame (RFC 6455, section 5.5).
const MAX_CONTROL_PAYLOAD: usize = 125;
/// Header of a client frame at its longest: two bytes, an eight-byte length
/// and the four-byte masking key.
const MAX_HEADER: usize = 14;
/// The only buffer a connection owns for reading.
const READ_BUFFER: usize = 4096;
/// The allocation of an incoming message starts at no more than this size
/// and doubles, never past the length its frames announced: a peer that
/// announces a large frame and sends nothing costs one step.
const BODY_STEP: usize = 4096;
/// Frames up to this size leave in a single write, header and payload
/// together.
const SMALL_FRAME: usize = 1024;
/// Text messages up to this size are read without asking the inbound budget:
/// what one connection can hold this way is this much, once.
pub const INBOUND_FREE: usize = 4096;
/// Text messages from this size on are charged to the large tiers of the
/// inbound budget; smaller ones above [`INBOUND_FREE`] to the small tiers.
pub const INBOUND_LARGE: usize = 64 * 1024;
/// One permit of an inbound tier stands for this many bytes.
const INBOUND_UNIT: usize = 1024;
/// Most data frames one message may be made of. A browser sends a message
/// in one frame. Without a bound, a peer could keep the reader busy with
/// empty fragments of a message it never finishes, none of which reaches
/// the caller's frame rate limit.
pub const MAX_MESSAGE_FRAMES: usize = 1024;
/// What the reader takes in from a peer it is closing on, after its own
/// Close frame, before it lets the connection go regardless.
const LINGER_BYTES: usize = 64 * 1024;

/// Status codes of Close frames (RFC 6455, section 7.4.1).
pub mod close_code {
    #[allow(dead_code)]
    pub const NORMAL: u16 = 1000;
    pub const GOING_AWAY: u16 = 1001;
    pub const PROTOCOL_ERROR: u16 = 1002;
    pub const INVALID_DATA: u16 = 1007;
    pub const POLICY: u16 = 1008;
    pub const TOO_BIG: u16 = 1009;
    pub const INTERNAL: u16 = 1011;
    pub const TRY_AGAIN_LATER: u16 = 1013;
}

/// Whether a Close frame may carry `code`: the codes of the RFC and of the
/// IANA registry that an endpoint may send, and the ranges for libraries and
/// applications. 1005, 1006 and 1015 stand for conditions, never for a code
/// on the wire.
fn close_code_allowed(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// One level of the inbound budget: so many bytes of incoming messages may
/// be in memory at once among the connections that share this tier.
#[derive(Debug, Clone)]
pub struct InboundTier {
    semaphore: Arc<Semaphore>,
    units: u32,
}

impl InboundTier {
    pub fn new(bytes: usize) -> Self {
        let units = (bytes / INBOUND_UNIT).clamp(1, Semaphore::MAX_PERMITS.min(u32::MAX as usize));
        Self {
            semaphore: Arc::new(Semaphore::new(units)),
            units: units as u32,
        }
    }

    /// Permits for `bytes`, never more than the tier has: a message larger
    /// than a whole tier takes all of it instead of waiting for ever.
    fn units_for(&self, bytes: usize) -> u32 {
        (bytes.div_ceil(INBOUND_UNIT).min(self.units as usize) as u32).max(1)
    }

    #[cfg(any(test, fuzzing))]
    pub fn available_bytes(&self) -> usize {
        self.semaphore.available_permits() * INBOUND_UNIT
    }
}

/// What bounds the memory that incoming messages occupy while they are being
/// received, across connections.
///
/// A message has to be whole before the relay can check and forward it, and
/// each connection may be receiving one. Without a bound, as many messages
/// as there are connections could be in memory together. With it, a
/// connection about to receive a message larger than [`INBOUND_FREE`] first
/// takes its size from every tier of its class, in order, and waits if a
/// tier is used up: it stops reading its socket, and TCP makes the sender
/// wait. What it took is given back when the caller asks for the next
/// message, that is, when it has finished with this one, or when the
/// message is abandoned.
///
/// There are two classes, so that pictures cannot starve text. Messages
/// below [`INBOUND_LARGE`] take from the small tiers, larger ones from the
/// large tiers.
///
/// A message that arrives in one frame is charged its length. A fragmented
/// one does not announce its final length, so it is charged the largest
/// size its class allows, once, when it grows past the lower bound of that
/// class: [`INBOUND_LARGE`] for the small class, the largest message the
/// connection accepts for the large class. Taking more later, while already
/// holding some, is how two connections would end up waiting for each
/// other; the order is fixed instead (the small class before the large one,
/// and within a class the tiers in the order given), and nothing is taken
/// out of that order.
#[derive(Debug, Clone, Default)]
pub struct InboundBudget {
    small: Vec<InboundTier>,
    large: Vec<InboundTier>,
}

impl InboundBudget {
    /// Within a class, tiers are taken in the order given: the narrowest
    /// first, so that a connection waiting for its own share holds nothing
    /// of the wider one.
    pub fn new(small: Vec<InboundTier>, large: Vec<InboundTier>) -> Self {
        Self { small, large }
    }

    fn is_empty(&self) -> bool {
        self.small.is_empty() && self.large.is_empty()
    }
}

/// What a client sent.
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    Text(String),
    /// A data message whose payload was read and discarded: a binary
    /// message, or any message once the reader has been told to discard.
    Binary,
    Ping(Vec<u8>),
    Pong,
    /// The peer started the closing handshake, with this status code if it
    /// gave one. The code has been checked; the reason, if any, was valid
    /// UTF-8 and has been dropped.
    Close(Option<u16>),
}

/// What the relay sends.
#[derive(Debug, Clone, Copy)]
pub enum Outgoing<'a> {
    Text(&'a str),
    Ping,
    Pong(&'a [u8]),
    /// A Close frame with this status code, or with none. Nothing can be
    /// sent after it.
    Close(Option<u16>),
}

#[derive(Debug)]
pub enum WsError {
    Io(io::Error),
    /// The peer broke the protocol; the text says how.
    Protocol(&'static str),
    /// A frame or a message is larger than the connection accepts.
    TooLarge,
    /// A message is made of more than [`MAX_MESSAGE_FRAMES`] frames.
    TooFragmented,
    /// A text message, or the reason of a Close frame, is not valid UTF-8.
    InvalidUtf8,
    /// The stream ended inside a frame or a fragmented message.
    Truncated,
    /// Nothing arrived in time, or a message was not finished in time.
    TimedOut {
        /// Whether a message had been started.
        in_message: bool,
    },
}

impl WsError {
    /// How a connection that met this error is to be closed.
    pub fn closing(&self) -> Closing {
        match self {
            WsError::Io(_) | WsError::Truncated => Closing::Abort,
            WsError::Protocol(_) => Closing::Fail(close_code::PROTOCOL_ERROR),
            WsError::TooLarge | WsError::TooFragmented => Closing::Fail(close_code::TOO_BIG),
            WsError::InvalidUtf8 => Closing::Fail(close_code::INVALID_DATA),
            WsError::TimedOut { in_message: true } => Closing::Fail(close_code::POLICY),
            WsError::TimedOut { in_message: false } => Closing::Fail(close_code::GOING_AWAY),
        }
    }
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsError::Io(error) => write!(f, "transport error: {error}"),
            WsError::Protocol(reason) => write!(f, "protocol violation: {reason}"),
            WsError::TooLarge => f.write_str("message larger than the connection accepts"),
            WsError::TooFragmented => f.write_str("message made of too many frames"),
            WsError::InvalidUtf8 => f.write_str("text is not valid UTF-8"),
            WsError::Truncated => f.write_str("stream ended inside a message"),
            WsError::TimedOut { in_message: true } => {
                f.write_str("message not finished within its deadline")
            }
            WsError::TimedOut { in_message: false } => f.write_str("nothing received in time"),
        }
    }
}

impl std::error::Error for WsError {}

impl From<io::Error> for WsError {
    fn from(error: io::Error) -> Self {
        WsError::Io(error)
    }
}

#[derive(Debug, Clone, Copy)]
struct FrameHead {
    fin: bool,
    opcode: u8,
    mask: [u8; 4],
    len: usize,
}

/// Parse a client frame header. `Ok(None)` means more bytes are needed.
fn parse_header(bytes: &[u8]) -> Result<Option<(FrameHead, usize)>, WsError> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let (first, second) = (bytes[0], bytes[1]);
    if first & 0x70 != 0 {
        return Err(WsError::Protocol("reserved bits set without an extension"));
    }
    let fin = first & 0x80 != 0;
    let opcode = first & 0x0F;
    if second & 0x80 == 0 {
        // A server must not accept an unmasked frame (RFC 6455, section 5.1).
        return Err(WsError::Protocol("frame from a client is not masked"));
    }
    // The length must be in its shortest form (RFC 6455, section 5.2).
    let (len, offset) = match second & 0x7F {
        126 => {
            if bytes.len() < 4 {
                return Ok(None);
            }
            let len = u64::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if len < 126 {
                return Err(WsError::Protocol("frame length not in its shortest form"));
            }
            (len, 4)
        }
        127 => {
            if bytes.len() < 10 {
                return Ok(None);
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[2..10]);
            let len = u64::from_be_bytes(raw);
            if len > i64::MAX as u64 {
                return Err(WsError::Protocol("frame length has its top bit set"));
            }
            if len <= u64::from(u16::MAX) {
                return Err(WsError::Protocol("frame length not in its shortest form"));
            }
            (len, 10)
        }
        short => (u64::from(short), 2),
    };
    if bytes.len() < offset + 4 {
        return Ok(None);
    }
    let mut mask = [0u8; 4];
    mask.copy_from_slice(&bytes[offset..offset + 4]);
    match opcode {
        OPCODE_CONTINUATION | OPCODE_TEXT | OPCODE_BINARY => {}
        OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG => {
            if !fin {
                return Err(WsError::Protocol("fragmented control frame"));
            }
            if len > MAX_CONTROL_PAYLOAD as u64 {
                return Err(WsError::Protocol("control frame longer than 125 bytes"));
            }
        }
        _ => return Err(WsError::Protocol("reserved opcode")),
    }
    // A length that does not fit the address space cannot be within any
    // limit the caller sets.
    let len = usize::try_from(len).map_err(|_| WsError::TooLarge)?;
    Ok(Some((
        FrameHead {
            fin,
            opcode,
            mask,
            len,
        },
        offset + 4,
    )))
}

/// Remove the client's masking from `data`, which starts `phase` bytes into
/// the payload of its frame.
fn unmask(data: &mut [u8], mask: [u8; 4], phase: usize) {
    let key = [
        mask[phase & 3],
        mask[(phase + 1) & 3],
        mask[(phase + 2) & 3],
        mask[(phase + 3) & 3],
    ];
    let wide = u64::from_ne_bytes([
        key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3],
    ]);
    let mut words = data.chunks_exact_mut(8);
    for word in &mut words {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(word);
        word.copy_from_slice(&(u64::from_ne_bytes(raw) ^ wide).to_ne_bytes());
    }
    for (index, byte) in words.into_remainder().iter_mut().enumerate() {
        *byte ^= key[index & 3];
    }
}

/// Check the bytes of `data` past `checked` as UTF-8, so that a text message
/// is refused at the first byte that cannot belong to valid text instead of
/// once all of it has arrived. A sequence cut by the end of what has arrived
/// so far is left to be checked with the bytes that complete it.
fn check_utf8(data: &[u8], checked: &mut usize) -> Result<(), WsError> {
    match std::str::from_utf8(&data[*checked..]) {
        Ok(_) => {
            *checked = data.len();
            Ok(())
        }
        Err(error) if error.error_len().is_none() => {
            *checked += error.valid_up_to();
            Ok(())
        }
        Err(_) => Err(WsError::InvalidUtf8),
    }
}

/// Check the payload of a Close frame (RFC 6455, sections 5.5.1 and 7.4)
/// and return its status code.
fn parse_close(payload: &[u8]) -> Result<Option<u16>, WsError> {
    match payload {
        [] => Ok(None),
        [_] => Err(WsError::Protocol("close frame with a one-byte payload")),
        [high, low, reason @ ..] => {
            let code = u16::from_be_bytes([*high, *low]);
            if !close_code_allowed(code) {
                return Err(WsError::Protocol("close frame with an invalid status code"));
            }
            std::str::from_utf8(reason).map_err(|_| WsError::InvalidUtf8)?;
            Ok(Some(code))
        }
    }
}

/// Header of a frame the server sends: final, unmasked.
fn encode_header(opcode: u8, len: usize) -> ([u8; 10], usize) {
    let mut head = [0u8; 10];
    head[0] = 0x80 | opcode;
    if len < 126 {
        head[1] = len as u8;
        (head, 2)
    } else if len <= usize::from(u16::MAX) {
        head[1] = 126;
        head[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        (head, 4)
    } else {
        head[1] = 127;
        head[2..10].copy_from_slice(&(len as u64).to_be_bytes());
        (head, 10)
    }
}

/// A data message under way: the frames of one message may be separated by
/// control frames, so this outlives a single frame.
#[derive(Debug)]
enum Assembly {
    /// The bytes of a text message so far, and how many of them are known
    /// to be valid UTF-8.
    Text { data: Vec<u8>, checked: usize },
    /// Bytes of a discarded message seen so far; they are not kept.
    Discard(usize),
}

impl Assembly {
    fn len(&self) -> usize {
        match self {
            Assembly::Text { data, .. } => data.len(),
            Assembly::Discard(seen) => *seen,
        }
    }
}

#[derive(Debug)]
struct FrameState {
    head: FrameHead,
    remaining: usize,
}

/// Which class of the inbound budget the message being assembled has been
/// charged to so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Charged {
    Nothing,
    Small,
    Large,
}

/// Bytes still to take from one class of the budget, and the tier of that
/// class to take them from next.
#[derive(Debug, Clone, Copy)]
struct Owed {
    bytes: usize,
    tier: usize,
}

/// The reading half of a connection.
///
/// `next` may be dropped at any await point and called again: everything it
/// has read is kept in `self`, never in the future.
pub struct WsReader<R> {
    io: R,
    buffer: Box<[u8; READ_BUFFER]>,
    start: usize,
    end: usize,
    frame: Option<FrameState>,
    message: Option<Assembly>,
    /// Data frames of the message being assembled.
    frames: usize,
    /// When the first frame of the message being assembled was read.
    message_started: Option<Instant>,
    control: Vec<u8>,
    max_message: usize,
    finished: bool,
    /// Data messages are read and dropped, whatever their type.
    discarding: bool,
    budget: InboundBudget,
    owed_small: Option<Owed>,
    owed_large: Option<Owed>,
    charged: Charged,
    /// Taken for the message being assembled.
    held: Vec<OwnedSemaphorePermit>,
    /// Taken for the message last handed to the caller.
    lent: Vec<OwnedSemaphorePermit>,
}

impl<R: AsyncRead + Unpin> WsReader<R> {
    pub fn new(io: R, max_message: usize) -> Self {
        Self {
            io,
            buffer: Box::new([0u8; READ_BUFFER]),
            start: 0,
            end: 0,
            frame: None,
            message: None,
            frames: 0,
            message_started: None,
            control: Vec::new(),
            max_message,
            finished: false,
            discarding: false,
            budget: InboundBudget::default(),
            owed_small: None,
            owed_large: None,
            charged: Charged::Nothing,
            held: Vec::new(),
            lent: Vec::new(),
        }
    }

    /// Make messages larger than [`INBOUND_FREE`] wait for room in `budget`
    /// before they are read.
    pub fn with_budget(mut self, budget: InboundBudget) -> Self {
        self.budget = budget;
        self
    }

    /// The next message, `None` once the peer has closed the stream between
    /// messages. After a close frame, an error or the end of the stream
    /// every later call returns `None`.
    ///
    /// Nothing here limits how long a peer may take; see [`Self::next_within`].
    pub async fn next(&mut self) -> Option<Result<Incoming, WsError>> {
        // The caller is done with the message it was given last.
        self.lent.clear();
        if self.finished {
            return None;
        }
        match self.read_message().await {
            Ok(Some(Incoming::Close(code))) => {
                self.finished = true;
                Some(Ok(Incoming::Close(code)))
            }
            Ok(Some(message)) => Some(Ok(message)),
            Ok(None) => {
                self.finished = true;
                None
            }
            Err(error) => {
                self.abandon();
                Some(Err(error))
            }
        }
    }

    /// Like [`Self::next`], giving the peer at most `limit` for it: `limit`
    /// from this call, and `limit` from the first frame of a data message
    /// to its last byte. Control frames inside a fragmented message are
    /// handed out as they come, and a call after one of them does not start
    /// the message's time again, so a peer cannot keep an unfinished
    /// message, and what it holds, alive by sending pings.
    ///
    /// A call that runs out of time ends the reader with
    /// [`WsError::TimedOut`].
    pub async fn next_within(&mut self, limit: Duration) -> Option<Result<Incoming, WsError>> {
        let mut deadline = Instant::now() + limit;
        if let Some(started) = self.message_started {
            deadline = deadline.min(started + limit);
        }
        match tokio::time::timeout_at(deadline, self.next()).await {
            Ok(item) => item,
            Err(_) => {
                let in_message = self.message.is_some();
                self.abandon();
                Some(Err(WsError::TimedOut { in_message }))
            }
        }
    }

    /// From now on read data messages without keeping, checking or
    /// budgeting them, and drop what has been assembled so far. For a
    /// connection that is closing and only waits for the peer's Close frame.
    pub fn discard(&mut self) {
        self.discarding = true;
        if let Some(message) = &mut self.message {
            *message = Assembly::Discard(message.len());
        }
        self.owed_small = None;
        self.owed_large = None;
        self.held.clear();
    }

    /// End the reader: what it was assembling goes, and so does what it
    /// holds of the budget.
    fn abandon(&mut self) {
        self.finished = true;
        self.message = None;
        self.frame = None;
        self.message_started = None;
        self.owed_small = None;
        self.owed_large = None;
        self.held.clear();
        self.lent.clear();
    }

    /// Read and drop what the peer still sends, up to `limit` bytes, until
    /// it closes its side. Used once the server has closed its own side, so
    /// that the connection ends in an orderly way and not with a reset that
    /// could discard the server's last frames before the peer reads them.
    async fn linger(&mut self, limit: usize) {
        self.abandon();
        let mut left = limit;
        while left > 0 {
            let room = READ_BUFFER.min(left);
            match self.io.read(&mut self.buffer[..room]).await {
                Ok(0) | Err(_) => return,
                Ok(read) => left -= read,
            }
        }
    }

    /// Read more bytes into the fixed buffer. Returns how many arrived.
    async fn fill(&mut self) -> io::Result<usize> {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.end == READ_BUFFER {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        let read = self.io.read(&mut self.buffer[self.end..]).await?;
        self.end += read;
        Ok(read)
    }

    fn begin_frame(&mut self, head: FrameHead) -> Result<(), WsError> {
        if head.len > self.max_message {
            return Err(WsError::TooLarge);
        }
        match head.opcode {
            OPCODE_TEXT | OPCODE_BINARY => {
                if self.message.is_some() {
                    return Err(WsError::Protocol(
                        "new data frame inside a fragmented message",
                    ));
                }
                self.message = Some(if head.opcode == OPCODE_TEXT && !self.discarding {
                    Assembly::Text {
                        data: Vec::new(),
                        checked: 0,
                    }
                } else {
                    Assembly::Discard(0)
                });
                self.frames = 1;
                self.message_started = Some(Instant::now());
            }
            OPCODE_CONTINUATION => {
                let Some(message) = &self.message else {
                    return Err(WsError::Protocol(
                        "continuation frame without a message to continue",
                    ));
                };
                if head.len > self.max_message - message.len() {
                    return Err(WsError::TooLarge);
                }
                self.frames += 1;
                if self.frames > MAX_MESSAGE_FRAMES {
                    return Err(WsError::TooFragmented);
                }
            }
            _ => self.control.clear(),
        }
        if head.opcode < OPCODE_CLOSE
            && !self.budget.is_empty()
            && let Some(Assembly::Text { data, .. }) = &self.message
        {
            let total = data.len() + head.len;
            let large = total >= INBOUND_LARGE;
            // A fragmented message above the free allowance takes the
            // largest size of the small class at once, unless this frame
            // already moves it into the large class with its final length.
            if self.charged < Charged::Small && total > INBOUND_FREE && !(large && head.fin) {
                self.charged = Charged::Small;
                self.owed_small = Some(Owed {
                    bytes: if head.fin {
                        total
                    } else {
                        INBOUND_LARGE.min(self.max_message)
                    },
                    tier: 0,
                });
            }
            if self.charged < Charged::Large && large {
                self.charged = Charged::Large;
                self.owed_large = Some(Owed {
                    bytes: if head.fin { total } else { self.max_message },
                    tier: 0,
                });
            }
        }
        self.frame = Some(FrameState {
            head,
            remaining: head.len,
        });
        Ok(())
    }

    /// Take what is owed to one class of the budget, a tier at a time. Each
    /// step is recorded before the next one starts, so a call that is
    /// dropped while it waits has lost nothing when it is repeated.
    async fn pay(
        owed: &mut Option<Owed>,
        tiers: &[InboundTier],
        held: &mut Vec<OwnedSemaphorePermit>,
    ) -> Result<(), WsError> {
        while let Some(Owed { bytes, tier }) = *owed {
            let Some(next) = tiers.get(tier) else {
                *owed = None;
                break;
            };
            let permit = next
                .semaphore
                .clone()
                .acquire_many_owned(next.units_for(bytes))
                .await
                .map_err(|_| WsError::Protocol("inbound budget is closed"))?;
            held.push(permit);
            *owed = Some(Owed {
                bytes,
                tier: tier + 1,
            });
        }
        Ok(())
    }

    async fn read_message(&mut self) -> Result<Option<Incoming>, WsError> {
        loop {
            if self.frame.is_none() {
                match parse_header(&self.buffer[self.start..self.end])? {
                    Some((head, used)) => {
                        self.start += used;
                        self.begin_frame(head)?;
                    }
                    None => {
                        let between_messages = self.start == self.end && self.message.is_none();
                        debug_assert!(self.end - self.start < MAX_HEADER);
                        if self.fill().await? == 0 {
                            return if between_messages {
                                Ok(None)
                            } else {
                                Err(WsError::Truncated)
                            };
                        }
                        continue;
                    }
                }
            }

            // Room in the budget before any of the body is read: the small
            // class first, then the large one.
            Self::pay(&mut self.owed_small, &self.budget.small, &mut self.held).await?;
            Self::pay(&mut self.owed_large, &self.budget.large, &mut self.held).await?;

            while let Some(frame) = self.frame.as_mut() {
                if frame.remaining == 0 {
                    break;
                }
                let phase = frame.head.len - frame.remaining;
                let mask = frame.head.mask;
                let is_control = frame.head.opcode >= OPCODE_CLOSE;

                if self.start < self.end {
                    // Bytes that arrived together with the header.
                    let take = frame.remaining.min(self.end - self.start);
                    let chunk = &mut self.buffer[self.start..self.start + take];
                    if is_control {
                        unmask(chunk, mask, phase);
                        self.control.extend_from_slice(chunk);
                    } else {
                        match self.message.as_mut() {
                            Some(Assembly::Text { data, checked }) => {
                                unmask(chunk, mask, phase);
                                if data.capacity() - data.len() < take {
                                    data.reserve_exact(
                                        frame.remaining.min(data.len().max(BODY_STEP)).max(take),
                                    );
                                }
                                data.extend_from_slice(chunk);
                                check_utf8(data, checked)?;
                            }
                            Some(Assembly::Discard(seen)) => *seen += take,
                            None => unreachable!("a data frame always has a message"),
                        }
                    }
                    self.start += take;
                    frame.remaining -= take;
                    continue;
                }

                match self.message.as_mut() {
                    Some(Assembly::Text { data, checked }) if !is_control => {
                        // Straight from the socket into the message.
                        if data.capacity() == data.len() {
                            data.reserve_exact(frame.remaining.min(data.len().max(BODY_STEP)));
                        }
                        let before = data.len();
                        let room = (data.capacity() - before).min(frame.remaining);
                        let read = (&mut self.io).take(room as u64).read_buf(data).await?;
                        if read == 0 {
                            return Err(WsError::Truncated);
                        }
                        unmask(&mut data[before..before + read], mask, phase);
                        frame.remaining -= read;
                        check_utf8(data, checked)?;
                    }
                    _ => {
                        // A control frame, or a message that is being
                        // discarded: through the fixed buffer.
                        if self.fill().await? == 0 {
                            return Err(WsError::Truncated);
                        }
                    }
                }
            }

            let Some(frame) = self.frame.take() else {
                continue;
            };
            match frame.head.opcode {
                OPCODE_PING => return Ok(Some(Incoming::Ping(std::mem::take(&mut self.control)))),
                OPCODE_PONG => {
                    self.control.clear();
                    return Ok(Some(Incoming::Pong));
                }
                OPCODE_CLOSE => {
                    let code = parse_close(&self.control);
                    self.control.clear();
                    return code.map(|code| Some(Incoming::Close(code)));
                }
                _ => {
                    if !frame.head.fin {
                        continue;
                    }
                    self.charged = Charged::Nothing;
                    self.frames = 0;
                    self.message_started = None;
                    self.lent = std::mem::take(&mut self.held);
                    return match self.message.take() {
                        Some(Assembly::Text { data, .. }) => String::from_utf8(data)
                            .map(|text| Some(Incoming::Text(text)))
                            .map_err(|_| WsError::InvalidUtf8),
                        Some(Assembly::Discard(_)) => Ok(Some(Incoming::Binary)),
                        None => unreachable!("a data frame always has a message"),
                    };
                }
            }
        }
    }
}

/// The writing half of a connection.
pub struct WsWriter<W> {
    io: W,
    /// Set while a frame is being written and left set if that write does
    /// not finish. A frame cut short leaves the stream in a state no later
    /// frame can repair, so nothing more is written after it.
    broken: bool,
    /// Set once a Close frame has been sent or attempted: nothing may follow
    /// it (RFC 6455, section 5.5.1).
    closed: bool,
    small: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> WsWriter<W> {
    pub fn new(io: W) -> Self {
        Self {
            io,
            broken: false,
            closed: false,
            small: Vec::new(),
        }
    }

    /// Write one frame and flush it. If the returned future is dropped
    /// before it completes, or fails, the writer refuses every later frame,
    /// and it refuses every frame after a Close frame.
    pub async fn send(&mut self, frame: Outgoing<'_>) -> io::Result<()> {
        let code;
        let (opcode, payload): (u8, &[u8]) = match frame {
            Outgoing::Text(text) => (OPCODE_TEXT, text.as_bytes()),
            Outgoing::Ping => (OPCODE_PING, &[]),
            Outgoing::Pong(payload) => {
                if payload.len() > MAX_CONTROL_PAYLOAD {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "control frame longer than 125 bytes",
                    ));
                }
                (OPCODE_PONG, payload)
            }
            Outgoing::Close(None) => (OPCODE_CLOSE, &[]),
            Outgoing::Close(Some(status)) => {
                if !close_code_allowed(status) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "status code that a close frame cannot carry",
                    ));
                }
                code = status.to_be_bytes();
                (OPCODE_CLOSE, &code)
            }
        };
        if self.broken {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "an earlier frame was not written in full",
            ));
        }
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "nothing can be sent after a close frame",
            ));
        }
        if opcode == OPCODE_CLOSE {
            self.closed = true;
        }
        self.broken = true;
        let (head, head_len) = encode_header(opcode, payload.len());
        if payload.len() <= SMALL_FRAME {
            self.small.clear();
            self.small.reserve_exact(head_len + payload.len());
            self.small.extend_from_slice(&head[..head_len]);
            self.small.extend_from_slice(payload);
            self.io.write_all(&self.small).await?;
        } else {
            self.io.write_all(&head[..head_len]).await?;
            self.io.write_all(payload).await?;
        }
        self.io.flush().await?;
        self.broken = false;
        Ok(())
    }

    /// Close the sending direction of the stream.
    async fn shutdown(&mut self) -> io::Result<()> {
        self.io.shutdown().await
    }
}

/// How a connection is to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closing {
    /// The peer sent a Close frame: answer with the same status code (none
    /// if it gave none) and close the stream.
    Answer(Option<u16>),
    /// The server ends the connection with this status code and waits for
    /// the peer's Close frame, discarding whatever data comes before it.
    Initiate(u16),
    /// The peer is at fault: say so with this status code and close the
    /// stream without processing anything more it sends (RFC 6455, section
    /// 7.1.7).
    Fail(u16),
    /// Nothing can be said: the stream is gone, or a frame was cut short and
    /// no frame can follow it.
    Abort,
}

/// The closing handshake (RFC 6455, section 7), bounded by `within`.
///
/// The server sends its Close frame, waits for the peer's if the server
/// started the handshake, and then closes its side of the TCP connection
/// first, as section 7.1.1 asks of a server. It then reads and drops up to
/// [`LINGER_BYTES`] until the peer closes its side, so that the connection
/// ends with both sides' FIN rather than a reset. A browser that has its
/// answer reports a clean close with the server's code instead of 1006.
///
/// Whatever the peer does, this returns within `within`: a peer that never
/// answers, never reads or never closes costs that time and nothing else.
/// Nothing read here is kept or charged to the budget.
pub async fn close<R, W>(
    writer: &mut WsWriter<W>,
    reader: &mut WsReader<R>,
    closing: Closing,
    within: Duration,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let handshake = async {
        let code = match closing {
            Closing::Abort => return,
            Closing::Answer(code) => code,
            Closing::Initiate(code) | Closing::Fail(code) => Some(code),
        };
        if writer.send(Outgoing::Close(code)).await.is_err() {
            return;
        }
        if let Closing::Initiate(_) = closing {
            reader.discard();
            while let Some(Ok(incoming)) = reader.next().await {
                if let Incoming::Close(_) = incoming {
                    break;
                }
            }
        }
        if writer.shutdown().await.is_ok() {
            reader.linger(LINGER_BYTES).await;
        }
    };
    let _ = tokio::time::timeout(within, handshake).await;
    reader.abandon();
}

type UpgradedIo = hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>;
pub type Reader = WsReader<ReadHalf<UpgradedIo>>;
pub type Writer = WsWriter<WriteHalf<UpgradedIo>>;

/// An accepted connection, before it is split into its two halves.
pub struct WsSocket {
    reader: Reader,
    writer: Writer,
}

impl WsSocket {
    pub fn split(self) -> (Writer, Reader) {
        (self.writer, self.reader)
    }
}

/// Extractor for a WebSocket handshake. It checks what RFC 6455 requires of
/// the request (section 4.2.1) and nothing about who is asking: that is the
/// caller's part.
pub struct WsUpgrade {
    key: HeaderValue,
    protocols: Vec<HeaderValue>,
    on_upgrade: hyper::upgrade::OnUpgrade,
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    })
}

/// Whether `key` is what section 4.1 of the RFC asks a client to send: 16
/// random bytes in Base64, 24 characters with padding.
fn valid_key(key: &HeaderValue) -> bool {
    key.len() == 24
        && STANDARD
            .decode(key.as_bytes())
            .is_ok_and(|bytes| bytes.len() == 16)
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for WsUpgrade
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let refuse = |status: StatusCode, reason: &'static str| (status, reason).into_response();
        if parts.method != Method::GET {
            return Err(refuse(
                StatusCode::METHOD_NOT_ALLOWED,
                "Request method must be `GET`",
            ));
        }
        if parts.version != Version::HTTP_11 {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "WebSocket handshake requires HTTP/1.1",
            ));
        }
        if !parts.headers.contains_key(HOST) {
            return Err(refuse(StatusCode::BAD_REQUEST, "`Host` header missing"));
        }
        if !header_has_token(&parts.headers, CONNECTION, "upgrade") {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "Connection header did not include 'upgrade'",
            ));
        }
        if !header_has_token(&parts.headers, UPGRADE, "websocket") {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "`Upgrade` header did not include 'websocket'",
            ));
        }
        if !header_has_token(&parts.headers, SEC_WEBSOCKET_VERSION, "13") {
            // Section 4.4: name the version this server speaks.
            let mut response = refuse(
                StatusCode::UPGRADE_REQUIRED,
                "`Sec-WebSocket-Version` header did not include '13'",
            );
            response
                .headers_mut()
                .insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
            return Err(response);
        }
        let mut keys = parts.headers.get_all(SEC_WEBSOCKET_KEY).iter();
        let key = match (keys.next(), keys.next()) {
            (Some(key), None) if valid_key(key) => key.clone(),
            (None, _) => {
                return Err(refuse(
                    StatusCode::BAD_REQUEST,
                    "`Sec-WebSocket-Key` header missing",
                ));
            }
            _ => {
                return Err(refuse(
                    StatusCode::BAD_REQUEST,
                    "`Sec-WebSocket-Key` header is not one Base64 encoding of 16 bytes",
                ));
            }
        };
        let protocols = parts
            .headers
            .get_all(SEC_WEBSOCKET_PROTOCOL)
            .iter()
            .cloned()
            .collect();
        let Some(on_upgrade) = parts.extensions.remove::<hyper::upgrade::OnUpgrade>() else {
            return Err(refuse(
                StatusCode::UPGRADE_REQUIRED,
                "WebSocket request couldn't be upgraded since no upgrade state was present",
            ));
        };
        Ok(Self {
            key,
            protocols,
            on_upgrade,
        })
    }
}

/// `Sec-WebSocket-Accept` for a `Sec-WebSocket-Key` (RFC 6455, section 4.2.2).
fn accept_key(key: &[u8]) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key);
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(sha1.finalize())
}

impl WsUpgrade {
    /// Whether the client offered `protocol` among its subprotocols. The
    /// names are compared exactly, as the RFC defines them.
    fn offered(&self, protocol: &str) -> bool {
        self.protocols.iter().any(|value| {
            value
                .to_str()
                .is_ok_and(|value| value.split(',').any(|offered| offered.trim() == protocol))
        })
    }

    /// Answer the handshake with `101 Switching Protocols` and run
    /// `callback` on the connection once the HTTP layer has let go of it.
    /// `protocol` is named as the subprotocol if the client offered it, and
    /// no subprotocol is named otherwise: a server may only select one the
    /// client asked for (section 4.2.2), and a browser fails the connection
    /// if it does not. `max_message` bounds one frame and one reassembled
    /// message alike; `budget` bounds how much of such messages is in memory
    /// at once across connections.
    pub fn on_upgrade<F, Fut>(
        self,
        protocol: &'static str,
        max_message: usize,
        budget: InboundBudget,
        callback: F,
    ) -> Response
    where
        F: FnOnce(WsSocket) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let offered = self.offered(protocol);
        let on_upgrade = self.on_upgrade;
        tokio::spawn(async move {
            let Ok(upgraded) = on_upgrade.await else {
                return;
            };
            let (read, write) = tokio::io::split(hyper_util::rt::TokioIo::new(upgraded));
            callback(WsSocket {
                reader: WsReader::new(read, max_message).with_budget(budget),
                writer: WsWriter::new(write),
            })
            .await;
        });

        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        let headers = response.headers_mut();
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        if let Ok(accept) = HeaderValue::from_str(&accept_key(self.key.as_bytes())) {
            headers.insert(SEC_WEBSOCKET_ACCEPT, accept);
        }
        if offered {
            headers.insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static(protocol));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{DuplexStream, duplex};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::Message as ClientMessage;
    use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::{Role, frame::coding::CloseCode};

    const MASK: [u8; 4] = [0x37, 0xFA, 0x21, 0x3D];
    const LIMIT: usize = 1 << 20;

    /// A frame as a client would put it on the wire.
    fn client_frame(first: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![first];
        if payload.len() < 126 {
            frame.push(0x80 | payload.len() as u8);
        } else if payload.len() <= usize::from(u16::MAX) {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(&MASK);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ MASK[index & 3]),
        );
        frame
    }

    fn text(payload: &str) -> Vec<u8> {
        client_frame(0x80 | OPCODE_TEXT, payload.as_bytes())
    }

    fn close_frame(payload: &[u8]) -> Vec<u8> {
        client_frame(0x80 | OPCODE_CLOSE, payload)
    }

    /// Feed `wire` to a reader in pieces of `piece` bytes and collect what
    /// it yields until the stream ends or fails.
    async fn read_all(wire: Vec<u8>, piece: usize, limit: usize) -> Vec<Result<Incoming, String>> {
        let (mut client, server) = duplex(64);
        let feeder = tokio::spawn(async move {
            for chunk in wire.chunks(piece.max(1)) {
                if client.write_all(chunk).await.is_err() {
                    return;
                }
            }
        });
        let mut reader = WsReader::new(server, limit);
        let mut seen = Vec::new();
        while let Some(item) = reader.next().await {
            seen.push(item.map_err(|error| error.to_string()));
        }
        assert!(
            reader.next().await.is_none(),
            "a finished reader stays finished"
        );
        // A reader that stopped on an error leaves the feeder blocked on a
        // full pipe: closing this end is what lets it finish.
        drop(reader);
        let _ = feeder.await;
        seen
    }

    async fn first_error(wire: Vec<u8>, limit: usize) -> String {
        let seen = read_all(wire, 7, limit).await;
        match seen.last() {
            Some(Err(error)) => error.clone(),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn unmasking_matches_the_definition_at_every_offset() {
        let plain: Vec<u8> = (0..97u32).map(|value| (value * 31 + 7) as u8).collect();
        for phase in 0..9 {
            for len in 0..plain.len() {
                let mut data: Vec<u8> = plain[..len]
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ MASK[(phase + index) & 3])
                    .collect();
                unmask(&mut data, MASK, phase);
                assert_eq!(data, &plain[..len], "phase {phase}, length {len}");
            }
        }
    }

    #[test]
    fn accept_key_matches_the_example_of_the_rfc() {
        assert_eq!(
            accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn a_key_must_be_sixteen_bytes_in_base64() {
        let key = |value: &str| valid_key(&HeaderValue::from_str(value).unwrap());
        assert!(key("dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(key("AAAAAAAAAAAAAAAAAAAAAA=="));
        for bad in [
            "",
            "x",
            "dGhlIHNhbXBsZSBub25jZQ",     // no padding
            "dGhlIHNhbXBsZSBub25jZQ=",    // short padding
            "dGhlIHNhbXBsZSBub25jZQ===",  // too long
            "dGhlIHNhbXBsZSBub25jZQ==AA", // trailing bytes
            "dGhlIHNhbXBsZSBub25jZ!==",   // not Base64
            "dGhlIHNhbXBsZSBub25jZRE=",   // 17 bytes
            "dGhlIHNhbXBsZSBub25j",       // 15 bytes
            "dGhlIHNhbXBsZSBub25jZR==",   // non-canonical trailing bits
        ] {
            assert!(!key(bad), "{bad:?} was accepted");
        }
    }

    #[test]
    fn close_codes_are_checked_as_the_rfc_and_the_registry_define_them() {
        for code in [
            1000u16, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999,
            4000, 4999,
        ] {
            assert!(close_code_allowed(code), "{code}");
        }
        for code in [
            0u16, 999, 1004, 1005, 1006, 1015, 1016, 1100, 2000, 2999, 5000, 65535,
        ] {
            assert!(!close_code_allowed(code), "{code}");
        }
    }

    #[test]
    fn server_headers_use_the_shortest_length_form() {
        assert_eq!(
            encode_header(OPCODE_TEXT, 0),
            ([0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2)
        );
        assert_eq!(encode_header(OPCODE_TEXT, 125).0[..2], [0x81, 125]);
        assert_eq!(encode_header(OPCODE_TEXT, 126).0[..4], [0x81, 126, 0, 126]);
        assert_eq!(
            encode_header(OPCODE_TEXT, 65535).0[..4],
            [0x81, 126, 0xFF, 0xFF]
        );
        let (head, len) = encode_header(OPCODE_TEXT, 65536);
        assert_eq!(
            (len, &head[..]),
            (10, &[0x81, 127, 0, 0, 0, 0, 0, 1, 0, 0][..])
        );
        assert_eq!(encode_header(OPCODE_CLOSE, 0).0[..2], [0x88, 0]);
        assert_eq!(encode_header(OPCODE_PING, 0).0[..2], [0x89, 0]);
    }

    #[tokio::test]
    async fn text_frames_of_every_length_form_arrive_whole_however_they_are_cut() {
        for len in [0usize, 1, 125, 126, 4095, 4096, 4097, 65535, 65536, 300_000] {
            let payload: String = (0..len)
                .map(|index| (b'a' + (index % 26) as u8) as char)
                .collect();
            for piece in [1usize, 3, 13, 4096, 1 << 20] {
                if piece == 1 && len > 70_000 {
                    continue;
                }
                let seen = read_all(text(&payload), piece, LIMIT).await;
                assert_eq!(seen.len(), 1, "length {len}, pieces of {piece}");
                match &seen[0] {
                    Ok(Incoming::Text(got)) => {
                        assert!(got == &payload, "length {len}, pieces of {piece}");
                        // The message owns exactly what it holds: a large
                        // one is not sitting in a buffer twice its size.
                        if len >= BODY_STEP {
                            assert_eq!(got.capacity(), len, "capacity for length {len}");
                        }
                    }
                    other => panic!("length {len}: {other:?}"),
                }
            }
        }
    }

    #[tokio::test]
    async fn several_messages_in_one_segment_are_all_delivered() {
        let mut wire = Vec::new();
        for index in 0..50 {
            wire.extend(text(&format!("message {index}")));
        }
        wire.extend(close_frame(&[]));
        let seen = read_all(wire, 1 << 20, LIMIT).await;
        assert_eq!(seen.len(), 51);
        for (index, item) in seen[..50].iter().enumerate() {
            assert_eq!(item, &Ok(Incoming::Text(format!("message {index}"))));
        }
        assert_eq!(seen[50], Ok(Incoming::Close(None)));
    }

    #[tokio::test]
    async fn a_fragmented_message_is_reassembled_around_control_frames() {
        let mut wire = client_frame(OPCODE_TEXT, b"one ");
        wire.extend(client_frame(0x80 | OPCODE_PING, b"are you there"));
        wire.extend(client_frame(OPCODE_CONTINUATION, b"two "));
        wire.extend(client_frame(0x80 | OPCODE_PONG, b""));
        wire.extend(client_frame(0x80 | OPCODE_CONTINUATION, b"three"));
        for piece in [1usize, 5, 4096] {
            let seen = read_all(wire.clone(), piece, LIMIT).await;
            assert_eq!(
                seen,
                vec![
                    Ok(Incoming::Ping(b"are you there".to_vec())),
                    Ok(Incoming::Pong),
                    Ok(Incoming::Text("one two three".to_string())),
                ]
            );
        }
    }

    #[tokio::test]
    async fn a_binary_message_is_reported_and_not_kept() {
        let mut wire = client_frame(0x80 | OPCODE_BINARY, &vec![0xAB; 200_000]);
        wire.extend(client_frame(OPCODE_BINARY, &[1, 2, 3]));
        wire.extend(client_frame(0x80 | OPCODE_CONTINUATION, &[4, 5]));
        wire.extend(text("after"));
        let seen = read_all(wire, 4096, LIMIT).await;
        assert_eq!(
            seen,
            vec![
                Ok(Incoming::Binary),
                Ok(Incoming::Binary),
                Ok(Incoming::Text("after".to_string())),
            ]
        );
    }

    #[tokio::test]
    async fn what_breaks_the_protocol_is_refused() {
        let mut unmasked = text("hello");
        unmasked[1] &= 0x7F;
        assert!(first_error(unmasked, LIMIT).await.contains("not masked"));

        for bit in [0x40u8, 0x20, 0x10] {
            let mut reserved_bit = text("hello");
            reserved_bit[0] |= bit;
            assert!(
                first_error(reserved_bit, LIMIT)
                    .await
                    .contains("reserved bits")
            );
        }

        for opcode in [0x3u8, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
            let wire = client_frame(0x80 | opcode, b"x");
            assert!(first_error(wire, LIMIT).await.contains("reserved opcode"));
        }

        let orphan = client_frame(0x80 | OPCODE_CONTINUATION, b"x");
        assert!(
            first_error(orphan, LIMIT)
                .await
                .contains("without a message")
        );

        let mut nested = client_frame(OPCODE_TEXT, b"first");
        nested.extend(text("second"));
        assert!(
            first_error(nested, LIMIT)
                .await
                .contains("inside a fragmented message")
        );

        let long_ping = client_frame(0x80 | OPCODE_PING, &[0u8; 126]);
        assert!(
            first_error(long_ping, LIMIT)
                .await
                .contains("longer than 125")
        );

        let split_ping = client_frame(OPCODE_PING, b"x");
        assert!(
            first_error(split_ping, LIMIT)
                .await
                .contains("fragmented control")
        );

        let mut top_bit = vec![0x80 | OPCODE_TEXT, 0x80 | 127];
        top_bit.extend_from_slice(&u64::MAX.to_be_bytes());
        top_bit.extend_from_slice(&MASK);
        assert!(first_error(top_bit, LIMIT).await.contains("top bit"));

        let invalid = client_frame(0x80 | OPCODE_TEXT, &[0xFF, 0xFE, 0xFD]);
        assert!(first_error(invalid, LIMIT).await.contains("UTF-8"));
    }

    #[tokio::test]
    async fn a_length_must_be_given_in_its_shortest_form() {
        // 124 bytes announced with the 16-bit form, 65535 with the 64-bit
        // form, 0 with either.
        let mut wire_16 = vec![0x80 | OPCODE_TEXT, 0x80 | 126, 0, 124];
        wire_16.extend_from_slice(&MASK);
        wire_16.extend(std::iter::repeat_n(b'a' ^ MASK[0], 124));
        assert!(first_error(wire_16, LIMIT).await.contains("shortest form"));

        for len in [0u64, 125, 126, 65535] {
            let mut wire_64 = vec![0x80 | OPCODE_TEXT, 0x80 | 127];
            wire_64.extend_from_slice(&len.to_be_bytes());
            wire_64.extend_from_slice(&MASK);
            assert!(
                first_error(wire_64, LIMIT).await.contains("shortest form"),
                "{len}"
            );
        }
        let mut zero_16 = vec![0x80 | OPCODE_TEXT, 0x80 | 126, 0, 0];
        zero_16.extend_from_slice(&MASK);
        assert!(first_error(zero_16, LIMIT).await.contains("shortest form"));

        // The boundaries themselves, in their own forms, are fine.
        for len in [125usize, 126, 65535, 65536] {
            let payload = "z".repeat(len);
            assert_eq!(
                read_all(text(&payload), 4096, LIMIT).await,
                vec![Ok(Incoming::Text(payload))]
            );
        }
    }

    #[tokio::test]
    async fn a_close_frame_is_checked_and_its_code_reported() {
        assert_eq!(
            read_all(close_frame(&[]), 3, LIMIT).await,
            vec![Ok(Incoming::Close(None))]
        );
        for code in [1000u16, 1001, 1003, 1011, 1014, 3000, 4999] {
            let mut payload = code.to_be_bytes().to_vec();
            payload.extend_from_slice("bye, ünd 終".as_bytes());
            assert_eq!(
                read_all(close_frame(&payload), 3, LIMIT).await,
                vec![Ok(Incoming::Close(Some(code)))]
            );
        }
        assert!(
            first_error(close_frame(&[0x03]), LIMIT)
                .await
                .contains("one-byte")
        );
        for code in [0u16, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000] {
            assert!(
                first_error(close_frame(&code.to_be_bytes()), LIMIT)
                    .await
                    .contains("invalid status code"),
                "{code}"
            );
        }
        assert!(
            first_error(close_frame(&[0x03, 0xE8, 0xCE, 0xBA, 0xE1]), LIMIT)
                .await
                .contains("UTF-8")
        );
    }

    #[tokio::test]
    async fn invalid_text_is_refused_at_the_first_bad_byte() {
        // The first fragment is already invalid: the error comes before the
        // ping that follows it, and before the rest of the message.
        let mut wire = client_frame(OPCODE_TEXT, &[b'o', b'k', 0xC0, 0xAF]);
        wire.extend(client_frame(0x80 | OPCODE_PING, b"later"));
        wire.extend(client_frame(0x80 | OPCODE_CONTINUATION, b"end"));
        let seen = read_all(wire, 5, LIMIT).await;
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(matches!(&seen[0], Err(error) if error.contains("UTF-8")));

        // Within one frame, before the frame is complete: the peer still
        // has most of it to send and keeps the stream open.
        let mut payload = vec![b'a'; 2000];
        payload[10] = 0xFF;
        let whole = client_frame(0x80 | OPCODE_TEXT, &payload);
        let (mut client, server) = duplex(1 << 16);
        client.write_all(&whole[..100]).await.unwrap();
        let mut reader = WsReader::new(server, LIMIT);
        let outcome = tokio::time::timeout(Duration::from_secs(5), reader.next())
            .await
            .expect("the error does not wait for the rest of the frame");
        assert!(matches!(outcome, Some(Err(WsError::InvalidUtf8))));

        // A code point cut across fragments is fine; an unfinished one at
        // the end of the message is not.
        let snowman = "\u{2603}".as_bytes();
        let mut cut = client_frame(OPCODE_TEXT, &snowman[..1]);
        cut.extend(client_frame(OPCODE_CONTINUATION, &snowman[1..2]));
        cut.extend(client_frame(0x80 | OPCODE_CONTINUATION, &snowman[2..]));
        assert_eq!(
            read_all(cut, 1, LIMIT).await,
            vec![Ok(Incoming::Text("\u{2603}".to_string()))]
        );
        let mut unfinished = client_frame(OPCODE_TEXT, b"x");
        unfinished.extend(client_frame(0x80 | OPCODE_CONTINUATION, &snowman[..2]));
        assert!(first_error(unfinished, LIMIT).await.contains("UTF-8"));
    }

    #[tokio::test]
    async fn a_message_may_not_be_made_of_too_many_frames() {
        let mut most = client_frame(OPCODE_TEXT, b"a");
        for _ in 0..MAX_MESSAGE_FRAMES - 2 {
            most.extend(client_frame(OPCODE_CONTINUATION, b""));
        }
        most.extend(client_frame(0x80 | OPCODE_CONTINUATION, b"b"));
        assert_eq!(
            read_all(most, 4096, LIMIT).await,
            vec![Ok(Incoming::Text("ab".to_string()))]
        );

        let mut too_many = client_frame(OPCODE_BINARY, b"");
        for _ in 0..MAX_MESSAGE_FRAMES {
            too_many.extend(client_frame(OPCODE_CONTINUATION, b""));
        }
        assert!(
            first_error(too_many, LIMIT)
                .await
                .contains("too many frames")
        );
    }

    #[tokio::test]
    async fn size_limits_apply_to_a_frame_and_to_a_reassembled_message() {
        let exact = "x".repeat(1000);
        assert_eq!(
            read_all(text(&exact), 4096, 1000).await,
            vec![Ok(Incoming::Text(exact))]
        );
        let over = text(&"x".repeat(1001));
        assert!(first_error(over, 1000).await.contains("larger than"));

        // Refused on the header alone: nothing of the body has to arrive.
        let mut announced = vec![0x80 | OPCODE_TEXT, 0x80 | 127];
        announced.extend_from_slice(&(1u64 << 40).to_be_bytes());
        announced.extend_from_slice(&MASK);
        assert!(first_error(announced, LIMIT).await.contains("larger than"));

        let mut pieces = client_frame(OPCODE_TEXT, &[b'a'; 600]);
        pieces.extend(client_frame(0x80 | OPCODE_CONTINUATION, &[b'b'; 401]));
        assert!(first_error(pieces, 1000).await.contains("larger than"));

        let mut binary = client_frame(OPCODE_BINARY, &[0; 600]);
        binary.extend(client_frame(0x80 | OPCODE_CONTINUATION, &[0; 401]));
        assert!(first_error(binary, 1000).await.contains("larger than"));
    }

    #[tokio::test]
    async fn a_large_announced_frame_costs_what_has_arrived_not_what_it_announces() {
        let mut wire = vec![0x80 | OPCODE_TEXT, 0x80 | 127];
        wire.extend_from_slice(&(900_000u64).to_be_bytes());
        wire.extend_from_slice(&MASK);
        wire.extend(std::iter::repeat_n(b'a' ^ MASK[0], 1)); // one byte of 900000
        let (mut client, server) = duplex(1 << 16);
        client.write_all(&wire).await.unwrap();
        let mut reader = WsReader::new(server, LIMIT);
        let waited = tokio::time::timeout(Duration::from_millis(100), reader.next()).await;
        assert!(waited.is_err(), "the frame is not complete");
        match &reader.message {
            Some(Assembly::Text { data, .. }) => assert!(data.capacity() <= BODY_STEP),
            other => panic!("{other:?}"),
        }
        drop(client);
    }

    #[tokio::test]
    async fn a_stream_that_ends_inside_a_message_is_an_error_and_between_messages_is_not() {
        assert!(read_all(Vec::new(), 1, LIMIT).await.is_empty());
        assert_eq!(
            read_all(text("whole"), 1, LIMIT).await,
            vec![Ok(Incoming::Text("whole".to_string()))]
        );

        let whole = text("truncated message");
        for cut in 1..whole.len() {
            let error = first_error(whole[..cut].to_vec(), LIMIT).await;
            assert!(error.contains("ended inside"), "cut at {cut}: {error}");
        }

        let open = client_frame(OPCODE_TEXT, b"never finished");
        assert!(first_error(open, LIMIT).await.contains("ended inside"));
    }

    #[tokio::test]
    async fn nothing_is_read_after_a_close_frame() {
        let mut wire = text("before");
        wire.extend(close_frame(&[0x03, 0xE8]));
        wire.extend(text("after"));
        assert_eq!(
            read_all(wire, 4096, LIMIT).await,
            vec![
                Ok(Incoming::Text("before".to_string())),
                Ok(Incoming::Close(Some(close_code::NORMAL)))
            ]
        );
    }

    #[tokio::test]
    async fn a_read_that_is_dropped_and_started_again_loses_nothing() {
        let mut wire = Vec::new();
        let first = "a".repeat(70_000);
        wire.extend(client_frame(OPCODE_TEXT, &first.as_bytes()[..30_000]));
        wire.extend(client_frame(0x80 | OPCODE_PING, b"mid"));
        wire.extend(client_frame(
            0x80 | OPCODE_CONTINUATION,
            &first.as_bytes()[30_000..],
        ));
        wire.extend(text("second"));

        let (mut client, server) = duplex(16);
        let feeder = tokio::spawn(async move {
            for chunk in wire.chunks(997) {
                client.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let small = InboundTier::new(1 << 20);
        let large = InboundTier::new(4 << 20);
        let mut reader = WsReader::new(server, LIMIT).with_budget(budget_of(&[&small], &[&large]));
        let mut seen = Vec::new();
        let mut dropped = 0usize;
        loop {
            // The future is polled once and thrown away, again and again.
            let mut attempt = Box::pin(reader.next());
            let outcome = futures_util::poll!(attempt.as_mut());
            drop(attempt);
            match outcome {
                std::task::Poll::Ready(Some(item)) => seen.push(item.unwrap()),
                std::task::Poll::Ready(None) => break,
                std::task::Poll::Pending => {
                    dropped += 1;
                    tokio::task::yield_now().await;
                }
            }
        }
        feeder.await.unwrap();
        assert!(dropped > 10, "the read was interrupted {dropped} times");
        assert_eq!(
            seen,
            vec![
                Incoming::Ping(b"mid".to_vec()),
                Incoming::Text(first),
                Incoming::Text("second".to_string()),
            ]
        );
        drop(reader);
        assert_eq!(small.available_bytes(), 1 << 20);
        assert_eq!(large.available_bytes(), 4 << 20);
    }

    #[tokio::test]
    async fn the_reader_keeps_nothing_of_a_message_it_has_delivered() {
        let big = "z".repeat(900_000);
        let mut wire = text(&big);
        wire.extend(text("small"));
        let (mut client, server) = duplex(1 << 16);
        let feeder = tokio::spawn(async move { client.write_all(&wire).await.unwrap() });
        let mut reader = WsReader::new(server, LIMIT);
        assert_eq!(reader.next().await.unwrap().unwrap(), Incoming::Text(big));
        assert!(reader.message.is_none());
        assert_eq!(reader.buffer.len(), READ_BUFFER);
        assert_eq!(reader.control.capacity(), 0);
        assert_eq!(
            reader.next().await.unwrap().unwrap(),
            Incoming::Text("small".to_string())
        );
        feeder.await.unwrap();
    }

    async fn written(frames: &[Outgoing<'_>]) -> Vec<u8> {
        let (client, server) = duplex(1 << 22);
        let mut writer = WsWriter::new(server);
        for frame in frames {
            writer.send(*frame).await.unwrap();
        }
        drop(writer);
        let mut wire = Vec::new();
        let mut client = client;
        client.read_to_end(&mut wire).await.unwrap();
        wire
    }

    #[tokio::test]
    async fn frames_are_written_final_and_unmasked() {
        assert_eq!(written(&[Outgoing::Text("Hello")]).await, b"\x81\x05Hello");
        assert_eq!(written(&[Outgoing::Ping]).await, [0x89, 0x00]);
        assert_eq!(written(&[Outgoing::Pong(b"abc")]).await, b"\x8A\x03abc");
        assert_eq!(written(&[Outgoing::Close(None)]).await, [0x88, 0x00]);
        assert_eq!(
            written(&[Outgoing::Close(Some(close_code::GOING_AWAY))]).await,
            [0x88, 0x02, 0x03, 0xE9]
        );

        for len in [
            125usize,
            126,
            SMALL_FRAME,
            SMALL_FRAME + 1,
            65535,
            65536,
            400_000,
        ] {
            let payload = "q".repeat(len);
            let wire = written(&[Outgoing::Text(&payload), Outgoing::Ping]).await;
            let (head, head_len) = encode_header(OPCODE_TEXT, len);
            assert_eq!(&wire[..head_len], &head[..head_len], "length {len}");
            assert!(
                &wire[head_len..head_len + len] == payload.as_bytes(),
                "length {len}"
            );
            assert_eq!(&wire[head_len + len..], [0x89, 0x00], "length {len}");
        }
    }

    #[tokio::test]
    async fn nothing_is_written_after_a_close_frame() {
        let (client, server) = duplex(1024);
        let mut writer = WsWriter::new(server);
        writer.send(Outgoing::Close(Some(1000))).await.unwrap();
        for frame in [
            Outgoing::Text("late"),
            Outgoing::Ping,
            Outgoing::Pong(b""),
            Outgoing::Close(None),
        ] {
            let refused = writer.send(frame).await.unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::BrokenPipe);
        }
        drop(writer);
        let mut wire = Vec::new();
        let mut client = client;
        client.read_to_end(&mut wire).await.unwrap();
        assert_eq!(wire, [0x88, 0x02, 0x03, 0xE8]);
    }

    #[tokio::test]
    async fn a_close_code_that_cannot_be_sent_is_refused_without_harming_the_writer() {
        let (_client, server) = duplex(1024);
        let mut writer = WsWriter::new(server);
        for code in [1005u16, 1006, 1015, 0, 5000] {
            assert_eq!(
                writer
                    .send(Outgoing::Close(Some(code)))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        writer.send(Outgoing::Text("still open")).await.unwrap();
    }

    #[tokio::test]
    async fn the_writer_keeps_nothing_of_a_frame_it_has_written() {
        let (client, server) = duplex(1 << 22);
        let mut writer = WsWriter::new(server);
        writer
            .send(Outgoing::Text(&"w".repeat(900_000)))
            .await
            .unwrap();
        writer.send(Outgoing::Text("small")).await.unwrap();
        assert!(writer.small.capacity() <= SMALL_FRAME + 10);
        drop(client);
    }

    #[tokio::test]
    async fn an_oversized_pong_is_refused_without_harming_the_writer() {
        let (_client, server) = duplex(1024);
        let mut writer = WsWriter::new(server);
        assert!(writer.send(Outgoing::Pong(&[0u8; 126])).await.is_err());
        writer.send(Outgoing::Ping).await.unwrap();
    }

    #[tokio::test]
    async fn a_write_cut_short_stops_every_later_frame() {
        // A peer that does not read: the pipe takes 64 bytes and no more.
        let (client, server) = duplex(64);
        let mut writer = WsWriter::new(server);
        let payload = "s".repeat(10_000);
        let cut = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            writer.send(Outgoing::Text(&payload)),
        )
        .await;
        assert!(cut.is_err(), "the write must still be pending");
        let later = writer.send(Outgoing::Close(None)).await.unwrap_err();
        assert_eq!(later.kind(), io::ErrorKind::BrokenPipe);
        drop(client);
    }

    fn budget_of(small: &[&InboundTier], large: &[&InboundTier]) -> InboundBudget {
        InboundBudget::new(
            small.iter().map(|tier| (*tier).clone()).collect(),
            large.iter().map(|tier| (*tier).clone()).collect(),
        )
    }

    #[tokio::test]
    async fn each_message_is_charged_to_its_class_while_the_caller_has_it() {
        let small_address = InboundTier::new(1 << 20);
        let small_global = InboundTier::new(2 << 20);
        let large_address = InboundTier::new(4 << 20);
        let large_global = InboundTier::new(8 << 20);
        let big = "b".repeat(300_000);
        let middle = "m".repeat(10_000);
        let free = "f".repeat(INBOUND_FREE);
        let mut wire = text(&free);
        wire.extend(text(&middle));
        wire.extend(text(&big));
        wire.extend(text("small again"));
        let (mut client, server) = duplex(1 << 16);
        let feeder = tokio::spawn(async move { client.write_all(&wire).await.unwrap() });
        let mut reader = WsReader::new(server, LIMIT).with_budget(budget_of(
            &[&small_address, &small_global],
            &[&large_address, &large_global],
        ));
        let available = || {
            [
                small_address.available_bytes(),
                small_global.available_bytes(),
                large_address.available_bytes(),
                large_global.available_bytes(),
            ]
        };
        let full = [1 << 20, 2 << 20, 4 << 20, 8 << 20];

        // Up to the free allowance: nothing is taken.
        assert_eq!(reader.next().await.unwrap().unwrap(), Incoming::Text(free));
        assert_eq!(available(), full);

        // A middle-sized message: the small class only.
        assert_eq!(
            reader.next().await.unwrap().unwrap(),
            Incoming::Text(middle)
        );
        let taken = 10_000usize.div_ceil(INBOUND_UNIT) * INBOUND_UNIT;
        assert_eq!(
            available(),
            [full[0] - taken, full[1] - taken, full[2], full[3]]
        );

        // A large one: the large class only, and the middle one is returned.
        let message = reader.next().await.unwrap().unwrap();
        assert!(message == Incoming::Text(big));
        let taken = 300_000usize.div_ceil(INBOUND_UNIT) * INBOUND_UNIT;
        assert_eq!(
            available(),
            [full[0], full[1], full[2] - taken, full[3] - taken]
        );

        // Asking for the next message is what says the last one is done with.
        assert_eq!(
            reader.next().await.unwrap().unwrap(),
            Incoming::Text("small again".to_string())
        );
        assert_eq!(available(), full);
        feeder.await.unwrap();
    }

    #[tokio::test]
    async fn a_large_message_waits_for_room_and_its_body_is_not_read_meanwhile() {
        let global = InboundTier::new(400_000);
        let big = "w".repeat(300_000);

        let (mut first_client, first_server) = duplex(1 << 16);
        let first_wire = text(&big);
        let first_feeder =
            tokio::spawn(async move { first_client.write_all(&first_wire).await.unwrap() });
        let mut first = WsReader::new(first_server, LIMIT).with_budget(budget_of(&[], &[&global]));
        assert!(first.next().await.unwrap().unwrap() == Incoming::Text(big.clone()));
        first_feeder.await.unwrap();

        // The second connection needs more than what is left.
        let (mut second_client, second_server) = duplex(1 << 12);
        let second_wire = text(&big);
        let second_feeder = tokio::spawn(async move {
            second_client.write_all(&second_wire).await.unwrap();
            second_client
        });
        let mut second =
            WsReader::new(second_server, LIMIT).with_budget(budget_of(&[], &[&global]));
        for _ in 0..3 {
            let waited =
                tokio::time::timeout(std::time::Duration::from_millis(40), second.next()).await;
            assert!(
                waited.is_err(),
                "the second message must wait for the first to be released"
            );
        }
        // It holds no allocation for the body it has not been allowed to read,
        // and the sender is stuck behind a pipe nobody empties.
        assert!(
            matches!(&second.message, Some(Assembly::Text { data, .. }) if data.capacity() == 0)
        );
        assert!(!second_feeder.is_finished());

        // The first connection moves on: its share returns, the second proceeds.
        drop(first);
        assert!(second.next().await.unwrap().unwrap() == Incoming::Text(big));
        drop(second_feeder.await.unwrap());
    }

    #[tokio::test]
    async fn a_fragmented_message_is_charged_once_per_class_at_the_largest_size_of_the_class() {
        let small = InboundTier::new(1 << 20);
        let large = InboundTier::new(4 << 20);
        let mut wire = client_frame(OPCODE_TEXT, &[b'a'; 40_000]);
        wire.extend(client_frame(OPCODE_CONTINUATION, &[b'b'; 40_000]));
        wire.extend(client_frame(0x80 | OPCODE_CONTINUATION, &[b'c'; 40_000]));
        wire.extend(text("next"));
        let (mut client, server) = duplex(1 << 16);
        let feeder = tokio::spawn(async move { client.write_all(&wire).await.unwrap() });
        let mut reader = WsReader::new(server, LIMIT).with_budget(budget_of(&[&small], &[&large]));
        match reader.next().await.unwrap().unwrap() {
            Incoming::Text(got) => assert_eq!(got.len(), 120_000),
            other => panic!("{other:?}"),
        }
        assert_eq!(small.available_bytes(), (1 << 20) - INBOUND_LARGE);
        assert_eq!(large.available_bytes(), (4 << 20) - LIMIT);
        assert_eq!(
            reader.next().await.unwrap().unwrap(),
            Incoming::Text("next".to_string())
        );
        assert_eq!(small.available_bytes(), 1 << 20);
        assert_eq!(large.available_bytes(), 4 << 20);
        feeder.await.unwrap();
    }

    /// The case of a peer that starts a message just below the large class,
    /// in a frame that is not final, and never finishes it.
    #[tokio::test]
    async fn unfinished_messages_below_the_large_class_are_bounded_by_the_small_class() {
        let small = InboundTier::new(3 * INBOUND_LARGE);
        let large = InboundTier::new(16 << 20);
        let fragment = vec![b'p'; 63 * 1024];
        let mut held = Vec::new();
        for _ in 0..3 {
            let (mut client, server) = duplex(1 << 17);
            client
                .write_all(&client_frame(OPCODE_TEXT, &fragment))
                .await
                .unwrap();
            let mut reader =
                WsReader::new(server, LIMIT).with_budget(budget_of(&[&small], &[&large]));
            let waited = tokio::time::timeout(Duration::from_millis(50), reader.next()).await;
            assert!(waited.is_err(), "the message is not finished");
            held.push((client, reader));
        }
        // Three unfinished messages took all of the small class...
        assert_eq!(small.available_bytes(), 0);
        assert_eq!(large.available_bytes(), 16 << 20);

        // ...so a fourth waits before any of its body is read or allocated.
        let (mut client, server) = duplex(1 << 17);
        client
            .write_all(&client_frame(OPCODE_TEXT, &fragment))
            .await
            .unwrap();
        let mut fourth = WsReader::new(server, LIMIT).with_budget(budget_of(&[&small], &[&large]));
        let waited = tokio::time::timeout(Duration::from_millis(50), fourth.next()).await;
        assert!(waited.is_err());
        assert!(
            matches!(&fourth.message, Some(Assembly::Text { data, .. }) if data.capacity() == 0)
        );

        // Small messages still pass: they are within the free allowance.
        let (mut chat_client, chat_server) = duplex(1 << 12);
        chat_client.write_all(&text("hello")).await.unwrap();
        let mut chat =
            WsReader::new(chat_server, LIMIT).with_budget(budget_of(&[&small], &[&large]));
        assert_eq!(
            chat.next().await.unwrap().unwrap(),
            Incoming::Text("hello".to_string())
        );

        // One of the first three gives up: the fourth gets its share.
        drop(held.pop());
        let waited = tokio::time::timeout(Duration::from_millis(200), fourth.next()).await;
        assert!(waited.is_err(), "the fourth message is not finished either");
        assert!(
            matches!(&fourth.message, Some(Assembly::Text { data, .. }) if data.len() == 63 * 1024)
        );
        drop(held);
        drop(fourth);
        drop(client);
        assert_eq!(small.available_bytes(), 3 * INBOUND_LARGE);
    }

    #[tokio::test]
    async fn pings_do_not_extend_the_deadline_of_an_unfinished_message() {
        let small = InboundTier::new(1 << 20);
        let large = InboundTier::new(4 << 20);
        let (mut client, server) = duplex(1 << 17);
        client
            .write_all(&client_frame(OPCODE_TEXT, &vec![b'p'; 63 * 1024]))
            .await
            .unwrap();
        let mut reader = WsReader::new(server, LIMIT).with_budget(budget_of(&[&small], &[&large]));
        let pinger = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(40)).await;
                if client
                    .write_all(&client_frame(0x80 | OPCODE_PING, b"still here"))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        let limit = Duration::from_millis(400);
        let started = Instant::now();
        let mut pings = 0;
        let error = loop {
            match reader.next_within(limit).await {
                Some(Ok(Incoming::Ping(_))) => pings += 1,
                Some(Err(error)) => break error,
                other => panic!("{other:?}"),
            }
        };
        let elapsed = started.elapsed();
        assert!(matches!(error, WsError::TimedOut { in_message: true }));
        assert_eq!(error.closing(), Closing::Fail(close_code::POLICY));
        assert!(pings >= 3, "{pings} pings arrived");
        assert!(elapsed >= limit && elapsed < limit * 3, "{elapsed:?}");
        // What the message held is returned and nothing more is read.
        assert_eq!(small.available_bytes(), 1 << 20);
        assert!(reader.message.is_none());
        assert!(reader.next().await.is_none());
        drop(reader);
        pinger.await.unwrap();
    }

    #[tokio::test]
    async fn between_messages_the_limit_starts_with_each_call() {
        let (mut client, server) = duplex(1024);
        let mut reader = WsReader::new(server, LIMIT);
        let sender = tokio::spawn(async move {
            for round in 0..4 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                client.write_all(&text(&format!("m{round}"))).await.unwrap();
            }
            client
        });
        let limit = Duration::from_millis(150);
        let started = Instant::now();
        for round in 0..4 {
            assert_eq!(
                reader.next_within(limit).await.unwrap().unwrap(),
                Incoming::Text(format!("m{round}"))
            );
        }
        assert!(started.elapsed() > limit * 2);
        let client = sender.await.unwrap();
        let silent = reader.next_within(limit).await;
        assert!(matches!(
            silent,
            Some(Err(WsError::TimedOut { in_message: false }))
        ));
        drop(client);
    }

    #[tokio::test]
    async fn the_budget_is_returned_when_a_connection_fails_or_goes_away() {
        let global = InboundTier::new(4 << 20);

        // Dropped while it holds a delivered message.
        let (mut client, server) = duplex(1 << 16);
        let wire = text(&"d".repeat(200_000));
        let feeder = tokio::spawn(async move { client.write_all(&wire).await.unwrap() });
        let mut reader = WsReader::new(server, LIMIT).with_budget(budget_of(&[], &[&global]));
        assert!(reader.next().await.unwrap().is_ok());
        assert!(global.available_bytes() < 4 << 20);
        drop(reader);
        assert_eq!(global.available_bytes(), 4 << 20);
        feeder.await.unwrap();

        // The stream ends inside a message that had been charged.
        let whole = text(&"e".repeat(200_000));
        let (mut client, server) = duplex(1 << 16);
        let cut = whole[..100_000].to_vec();
        let feeder = tokio::spawn(async move { client.write_all(&cut).await.unwrap() });
        let mut reader = WsReader::new(server, LIMIT).with_budget(budget_of(&[], &[&global]));
        assert!(reader.next().await.unwrap().is_err());
        assert_eq!(global.available_bytes(), 4 << 20);
        feeder.await.unwrap();
    }

    #[tokio::test]
    async fn a_message_larger_than_a_tier_takes_the_tier_and_does_not_wait_for_ever() {
        let narrow = InboundTier::new(100_000);
        let wire = text(&"n".repeat(300_000));
        let (mut client, server) = duplex(1 << 16);
        let feeder = tokio::spawn(async move { client.write_all(&wire).await.unwrap() });
        let mut reader = WsReader::new(server, LIMIT).with_budget(budget_of(&[], &[&narrow]));
        assert!(reader.next().await.unwrap().is_ok());
        assert_eq!(narrow.available_bytes(), 0);
        feeder.await.unwrap();
    }

    /// The other end is an independent implementation of the protocol.
    async fn pair(
        limit: usize,
    ) -> (
        WebSocketStream<DuplexStream>,
        WsReader<ReadHalf<DuplexStream>>,
        WsWriter<WriteHalf<DuplexStream>>,
    ) {
        let (client_io, server_io) = duplex(1 << 16);
        let client = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;
        let (read, write) = tokio::io::split(server_io);
        (client, WsReader::new(read, limit), WsWriter::new(write))
    }

    #[tokio::test]
    async fn an_independent_client_and_this_transport_understand_each_other() {
        let (mut client, mut reader, mut writer) = pair(8 << 20).await;

        for len in [0usize, 5, 125, 126, 70_000, 3_000_000] {
            let payload: String = (0..len)
                .map(|index| (b'0' + (index % 10) as u8) as char)
                .collect();

            let outbound = payload.clone();
            let sending = tokio::spawn(async move {
                client.send(ClientMessage::Text(outbound)).await.unwrap();
                client
            });
            assert!(
                reader.next().await.unwrap().unwrap() == Incoming::Text(payload.clone()),
                "client to relay, {len}"
            );
            client = sending.await.unwrap();

            let receiving = tokio::spawn(async move {
                let message = client.next().await.unwrap().unwrap();
                (client, message)
            });
            writer.send(Outgoing::Text(&payload)).await.unwrap();
            let (returned, message) = receiving.await.unwrap();
            client = returned;
            assert!(
                message == ClientMessage::Text(payload),
                "relay to client, {len}"
            );
        }

        client
            .send(ClientMessage::Ping(b"ping".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            reader.next().await.unwrap().unwrap(),
            Incoming::Ping(b"ping".to_vec())
        );
        writer.send(Outgoing::Pong(b"ping")).await.unwrap();
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            ClientMessage::Pong(b"ping".to_vec())
        );

        // The client answers a ping from the relay by itself.
        writer.send(Outgoing::Ping).await.unwrap();
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            ClientMessage::Ping(Vec::new())
        );
        client.flush().await.unwrap();
        assert_eq!(reader.next().await.unwrap().unwrap(), Incoming::Pong);

        client
            .send(ClientMessage::Binary(vec![1, 2, 3]))
            .await
            .unwrap();
        assert_eq!(reader.next().await.unwrap().unwrap(), Incoming::Binary);

        client.close(None).await.unwrap();
        assert_eq!(reader.next().await.unwrap().unwrap(), Incoming::Close(None));
        assert!(reader.next().await.is_none());
    }

    const WITHIN: Duration = Duration::from_secs(5);

    /// What the client library reports once the connection is over: the
    /// Close frame it got, if any, and whether the stream then ended
    /// cleanly.
    /// The client is dropped at the end, as a browser closes its socket once
    /// the server has closed its side.
    async fn client_sees_close(
        mut client: WebSocketStream<DuplexStream>,
    ) -> (Option<CloseFrame<'static>>, bool) {
        let mut close = None;
        loop {
            match client.next().await {
                Some(Ok(ClientMessage::Close(frame))) => close = frame,
                Some(Ok(_)) => continue,
                None => return (close, true),
                Some(Err(_)) => return (close, false),
            }
        }
    }

    #[tokio::test]
    async fn a_close_from_the_client_is_answered_with_its_code() {
        let (mut client, mut reader, mut writer) = pair(LIMIT).await;
        client
            .close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "Page unload".into(),
            }))
            .await
            .unwrap();
        let Some(Ok(Incoming::Close(code))) = reader.next().await else {
            panic!("no close frame");
        };
        assert_eq!(code, Some(close_code::NORMAL));
        let started = Instant::now();
        let (closed, (frame, clean)) = tokio::join!(
            close(&mut writer, &mut reader, Closing::Answer(code), WITHIN),
            client_sees_close(client),
        );
        let () = closed;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(frame.map(|frame| frame.code), Some(CloseCode::Normal));
        assert!(clean, "the stream ended cleanly after the handshake");
    }

    #[tokio::test]
    async fn a_close_without_a_code_is_answered_without_one() {
        let (mut client, mut reader, mut writer) = pair(LIMIT).await;
        client.close(None).await.unwrap();
        assert_eq!(reader.next().await.unwrap().unwrap(), Incoming::Close(None));
        let ((), (frame, clean)) = tokio::join!(
            close(&mut writer, &mut reader, Closing::Answer(None), WITHIN),
            client_sees_close(client),
        );
        assert!(frame.is_none());
        assert!(clean);
    }

    #[tokio::test]
    async fn a_close_started_by_the_server_waits_for_the_answer_and_ends_cleanly() {
        let (mut client, mut reader, mut writer) = pair(LIMIT).await;
        // The client is still sending when the server decides to close:
        // what it sends before its answer is read and dropped.
        client
            .send(ClientMessage::Text("x".repeat(30_000)))
            .await
            .unwrap();
        let started = Instant::now();
        let ((), (frame, clean)) = tokio::join!(
            close(
                &mut writer,
                &mut reader,
                Closing::Initiate(close_code::GOING_AWAY),
                WITHIN
            ),
            client_sees_close(client),
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(frame.map(|frame| frame.code), Some(CloseCode::Away));
        assert!(clean);
    }

    #[tokio::test]
    async fn a_peer_that_never_answers_costs_the_closing_time_and_no_more() {
        // A peer that reads nothing and sends nothing.
        let (peer, server) = duplex(64);
        let (read, write) = tokio::io::split(server);
        let mut reader = WsReader::new(read, LIMIT);
        let mut writer = WsWriter::new(write);
        let within = Duration::from_millis(300);
        let started = Instant::now();
        close(
            &mut writer,
            &mut reader,
            Closing::Initiate(close_code::POLICY),
            within,
        )
        .await;
        let elapsed = started.elapsed();
        assert!(elapsed >= within && elapsed < within * 3, "{elapsed:?}");
        drop(peer);

        // A peer that floods the server while it closes on it.
        let (mut peer, server) = duplex(1 << 16);
        let (read, write) = tokio::io::split(server);
        let mut reader = WsReader::new(read, LIMIT);
        let mut writer = WsWriter::new(write);
        let flood = tokio::spawn(async move {
            let frame = client_frame(0x80 | OPCODE_BINARY, &[7u8; 60_000]);
            let mut sent = 0usize;
            while peer.write_all(&frame).await.is_ok() {
                sent += frame.len();
            }
            sent
        });
        let started = Instant::now();
        close(
            &mut writer,
            &mut reader,
            Closing::Fail(close_code::PROTOCOL_ERROR),
            within,
        )
        .await;
        assert!(started.elapsed() < within * 3);
        drop((reader, writer));
        let sent = flood.await.unwrap();
        // What the server read of it after its Close is bounded.
        assert!(sent <= LINGER_BYTES + (1 << 16) + 120_000, "{sent}");
    }

    #[tokio::test]
    async fn an_abort_sends_nothing() {
        let (client, server) = duplex(1024);
        let (read, write) = tokio::io::split(server);
        let mut reader = WsReader::new(read, LIMIT);
        let mut writer = WsWriter::new(write);
        close(&mut writer, &mut reader, Closing::Abort, WITHIN).await;
        drop((reader, writer));
        let mut wire = Vec::new();
        let mut client = client;
        client.read_to_end(&mut wire).await.unwrap();
        assert!(wire.is_empty());
    }

    #[tokio::test]
    async fn errors_say_how_the_connection_is_to_be_closed() {
        assert_eq!(
            WsError::Protocol("x").closing(),
            Closing::Fail(close_code::PROTOCOL_ERROR)
        );
        assert_eq!(
            WsError::InvalidUtf8.closing(),
            Closing::Fail(close_code::INVALID_DATA)
        );
        assert_eq!(
            WsError::TooLarge.closing(),
            Closing::Fail(close_code::TOO_BIG)
        );
        assert_eq!(
            WsError::TooFragmented.closing(),
            Closing::Fail(close_code::TOO_BIG)
        );
        assert_eq!(WsError::Truncated.closing(), Closing::Abort);
        assert_eq!(
            WsError::Io(io::ErrorKind::ConnectionReset.into()).closing(),
            Closing::Abort
        );
    }

    /// The handshake against a real HTTP server, as a browser would do it.
    async fn handshake(request: &str) -> String {
        use axum::{Router, routing::get};
        async fn upgrade(ws: WsUpgrade) -> Response {
            ws.on_upgrade("pinchat.v1", LIMIT, InboundBudget::default(), |_| async {})
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/", get(upgrade)))
                .await
                .unwrap()
        });
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let mut buffer = [0u8; 1024];
        while !response.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..read]);
        }
        server.abort();
        String::from_utf8_lossy(&response).to_lowercase()
    }

    fn request(extra: &str) -> String {
        format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n{extra}\r\n"
        )
    }

    #[tokio::test]
    async fn the_handshake_checks_the_key_and_names_only_an_offered_subprotocol() {
        let key = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";

        let offered = handshake(&request(&format!(
            "{key}Sec-WebSocket-Protocol: other, pinchat.v1\r\n"
        )))
        .await;
        assert!(offered.starts_with("http/1.1 101"), "{offered}");
        assert!(offered.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="));
        assert!(offered.contains("sec-websocket-protocol: pinchat.v1\r\n"));

        for not_offered in [
            String::new(),
            "Sec-WebSocket-Protocol: other\r\n".to_string(),
            "Sec-WebSocket-Protocol: PINCHAT.V1\r\n".to_string(),
            "Sec-WebSocket-Protocol: pinchat.v1.jwt.x\r\n".to_string(),
        ] {
            let answer = handshake(&request(&format!("{key}{not_offered}"))).await;
            assert!(answer.starts_with("http/1.1 101"), "{answer}");
            assert!(!answer.contains("sec-websocket-protocol"), "{answer}");
        }

        for bad_key in [
            "",
            "Sec-WebSocket-Key: short\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        ] {
            let answer = handshake(&request(bad_key)).await;
            assert!(answer.starts_with("http/1.1 400"), "{bad_key:?}: {answer}");
        }

        let old_version = handshake(&request(key).replace("Version: 13", "Version: 8")).await;
        assert!(old_version.starts_with("http/1.1 426"), "{old_version}");
        assert!(old_version.contains("sec-websocket-version: 13"));
    }

    #[tokio::test]
    async fn the_client_library_accepts_the_close_frame_of_the_relay() {
        let (mut client, _reader, mut writer) = pair(LIMIT).await;
        writer.send(Outgoing::Text("bye")).await.unwrap();
        writer
            .send(Outgoing::Close(Some(close_code::GOING_AWAY)))
            .await
            .unwrap();
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            ClientMessage::Text("bye".to_string())
        );
        assert!(matches!(
            client.next().await.unwrap().unwrap(),
            ClientMessage::Close(Some(CloseFrame {
                code: CloseCode::Away,
                ..
            }))
        ));
    }
}
