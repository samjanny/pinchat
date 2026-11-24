//! Shared parts of the fuzz targets: the transport under test, an allocator
//! that counts, streams that cut reads and writes where the input says, and
//! a reference model of what RFC 6455 lets a server accept.

#[allow(dead_code)]
#[path = "../../src/ws_transport.rs"]
pub mod ws_transport;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// ---------------------------------------------------------------------------
// Allocation accounting
// ---------------------------------------------------------------------------

/// The system allocator, counting what is live, the most that was live at
/// once and the largest single request since the last [`reset_peak`].
pub struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grew(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, size) };
        if !moved.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            grew(size);
        }
        moved
    }
}

fn grew(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
    LARGEST.fetch_max(size, Ordering::Relaxed);
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Start a measurement. Returns what is live now.
pub fn reset_peak() -> usize {
    let live = LIVE.load(Ordering::Relaxed);
    PEAK.store(live, Ordering::Relaxed);
    LARGEST.store(0, Ordering::Relaxed);
    live
}

/// The most that was live at once, and the largest single request, since
/// [`reset_peak`].
pub fn peak() -> (usize, usize) {
    (
        PEAK.load(Ordering::Relaxed),
        LARGEST.load(Ordering::Relaxed),
    )
}

pub fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Input-driven decisions
// ---------------------------------------------------------------------------

/// Decisions taken from a byte string, cycled; all zero when it is empty.
#[derive(Clone)]
pub struct Plan {
    bytes: Vec<u8>,
    at: usize,
}

impl Plan {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            at: 0,
        }
    }

    /// The next decision. An empty plan, or one used up, goes on with a
    /// fixed pseudo-random sequence mixed with it, so that a short input
    /// does not mean one-byte reads for ever.
    pub fn byte(&mut self) -> u8 {
        let step = self.at;
        self.at = self.at.wrapping_add(1);
        let mixed = (step as u64 ^ 0x9E37_79B9_7F4A_7C15)
            .wrapping_mul(0xBF58_476D_1CE4_E5B9)
            .rotate_left(31);
        if self.bytes.is_empty() {
            return (mixed >> 24) as u8;
        }
        let value = self.bytes[step % self.bytes.len()];
        if step < self.bytes.len() {
            value
        } else {
            value ^ (mixed >> 24) as u8
        }
    }
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

/// A peer that sends `data` in reads of the sizes the plan picks, and now
/// and then has nothing yet: the read is pending once, and ready the next
/// time it is polled. Then the stream ends.
pub struct ScriptedReader {
    data: Vec<u8>,
    at: usize,
    plan: Plan,
    pending_now: bool,
    /// Reads that returned something, the end of the stream included.
    progress: Rc<Cell<usize>>,
}

impl ScriptedReader {
    pub fn new(data: Vec<u8>, plan: Plan) -> Self {
        Self {
            data,
            at: 0,
            plan,
            pending_now: false,
            progress: Rc::new(Cell::new(0)),
        }
    }

    /// A counter of the reads that returned something, which stays readable
    /// once the stream belongs to a reader.
    pub fn progress(&self) -> Rc<Cell<usize>> {
        self.progress.clone()
    }
}

impl AsyncRead for ScriptedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.pending_now && this.plan.byte() % 5 == 0 {
            this.pending_now = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.pending_now = false;
        let left = this.data.len() - this.at;
        let want = match this.plan.byte() % 4 {
            0 => 1,
            1 => usize::from(this.plan.byte()) + 1,
            2 => usize::from(u16::from_le_bytes([this.plan.byte(), this.plan.byte()])) + 1,
            _ => usize::MAX,
        };
        let take = left.min(buf.remaining()).min(want);
        buf.put_slice(&this.data[this.at..this.at + take]);
        this.at += take;
        this.progress.set(this.progress.get() + 1);
        Poll::Ready(Ok(()))
    }
}

/// A peer that takes what is written in pieces of the sizes the plan picks,
/// and is sometimes not ready. What it took stays readable through
/// [`ScriptedWriter::received`] after the writer that owns it is gone.
pub struct ScriptedWriter {
    received: Rc<RefCell<Vec<u8>>>,
    shut: Rc<Cell<bool>>,
    plan: Plan,
    pending_now: bool,
}

/// What a [`ScriptedWriter`] took, and whether its sending side was shut.
#[derive(Clone)]
pub struct Received {
    pub bytes: Rc<RefCell<Vec<u8>>>,
    pub shut: Rc<Cell<bool>>,
}

impl ScriptedWriter {
    pub fn new(plan: Plan) -> (Self, Received) {
        let bytes = Rc::new(RefCell::new(Vec::new()));
        let shut = Rc::new(Cell::new(false));
        (
            Self {
                received: bytes.clone(),
                shut: shut.clone(),
                plan,
                pending_now: false,
            },
            Received { bytes, shut },
        )
    }
}

impl AsyncWrite for ScriptedWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        assert!(!this.shut.get(), "written after shutdown");
        if !this.pending_now && this.plan.byte() % 4 == 0 {
            this.pending_now = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.pending_now = false;
        let take = buf.len().min(usize::from(this.plan.byte()) * 37 + 1);
        this.received.borrow_mut().extend_from_slice(&buf[..take]);
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shut.set(true);
        Poll::Ready(Ok(()))
    }
}

/// Poll `future` once with a waker that does nothing.
pub fn poll_once<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    let mut cx = Context::from_waker(Waker::noop());
    future.poll(&mut cx)
}

// ---------------------------------------------------------------------------
// Frames and the reference model
// ---------------------------------------------------------------------------

/// How a frame's length is written. RFC 6455 asks for the shortest form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthForm {
    Shortest,
    Sixteen,
    SixtyFour,
}

#[derive(Debug, Clone)]
pub struct FrameSpec {
    pub fin: bool,
    pub rsv: u8,
    pub opcode: u8,
    pub masked: bool,
    pub mask: [u8; 4],
    pub form: LengthForm,
    pub payload: Vec<u8>,
}

impl FrameSpec {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(
            (if self.fin { 0x80 } else { 0 }) | ((self.rsv & 7) << 4) | (self.opcode & 0x0F),
        );
        let mask_bit = if self.masked { 0x80 } else { 0 };
        let len = self.payload.len();
        let form = match self.form {
            LengthForm::Shortest if len < 126 => 0,
            LengthForm::Shortest if len <= usize::from(u16::MAX) => 1,
            LengthForm::Shortest => 2,
            LengthForm::Sixteen if len <= usize::from(u16::MAX) => 1,
            LengthForm::Sixteen | LengthForm::SixtyFour => 2,
        };
        match form {
            0 => out.push(mask_bit | len as u8),
            1 => {
                out.push(mask_bit | 126);
                out.extend_from_slice(&(len as u16).to_be_bytes());
            }
            _ => {
                out.push(mask_bit | 127);
                out.extend_from_slice(&(len as u64).to_be_bytes());
            }
        }
        if self.masked {
            out.extend_from_slice(&self.mask);
            out.extend(
                self.payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ self.mask[index & 3]),
            );
        } else {
            out.extend_from_slice(&self.payload);
        }
    }

    /// Whether the length was written in its shortest form.
    fn shortest(&self) -> bool {
        let len = self.payload.len();
        match self.form {
            LengthForm::Shortest => true,
            LengthForm::Sixteen => len >= 126 || len > usize::from(u16::MAX),
            LengthForm::SixtyFour => len > usize::from(u16::MAX),
        }
    }
}

/// What the reader yields, without the payload of discarded messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    Text(String),
    Binary,
    Ping(Vec<u8>),
    Pong,
    Close(Option<u16>),
    /// The error, by kind.
    Error(&'static str),
}

pub fn kind(error: &ws_transport::WsError) -> &'static str {
    use ws_transport::WsError::*;
    match error {
        Io(_) => "io",
        Protocol(_) => "protocol",
        TooLarge => "too large",
        TooFragmented => "too fragmented",
        InvalidUtf8 => "utf-8",
        Truncated => "truncated",
        TimedOut { .. } => "timed out",
    }
}

pub fn seen(item: Result<ws_transport::Incoming, ws_transport::WsError>) -> Seen {
    use ws_transport::Incoming;
    match item {
        Ok(Incoming::Text(text)) => Seen::Text(text),
        Ok(Incoming::Binary) => Seen::Binary,
        Ok(Incoming::Ping(payload)) => Seen::Ping(payload),
        Ok(Incoming::Pong) => Seen::Pong,
        Ok(Incoming::Close(code)) => Seen::Close(code),
        Err(error) => Seen::Error(kind(&error)),
    }
}

/// Status codes a Close frame may carry, written from the RFC and the IANA
/// registry independently of the transport's own table.
fn sendable_close_code(code: u16) -> bool {
    (1000..=1003).contains(&code) || (1007..=1014).contains(&code) || (3000..=4999).contains(&code)
}

/// Whether `bytes` holds an invalid UTF-8 sequence, as opposed to valid
/// text that may end inside a code point.
fn invalid_so_far(bytes: &[u8]) -> bool {
    match std::str::from_utf8(bytes) {
        Ok(_) => false,
        Err(error) => error.error_len().is_some(),
    }
}

/// What a server that follows RFC 6455 to the letter, with the transport's
/// limits, yields for `frames` followed by the end of the stream.
pub fn model(frames: &[FrameSpec], limit: usize) -> Vec<Seen> {
    let mut out = Vec::new();
    // (text?, bytes so far, frames so far)
    let mut message: Option<(bool, Vec<u8>, usize)> = None;
    for frame in frames {
        let control = frame.opcode >= 0x8;
        // Header, in the order the transport checks it.
        if frame.rsv != 0 {
            out.push(Seen::Error("protocol"));
            return out;
        }
        if !frame.masked {
            out.push(Seen::Error("protocol"));
            return out;
        }
        if !frame.shortest() {
            out.push(Seen::Error("protocol"));
            return out;
        }
        match frame.opcode {
            0x0..=0x2 => {}
            0x8..=0xA => {
                if !frame.fin {
                    out.push(Seen::Error("protocol"));
                    return out;
                }
                if frame.payload.len() > 125 {
                    out.push(Seen::Error("protocol"));
                    return out;
                }
            }
            _ => {
                out.push(Seen::Error("protocol"));
                return out;
            }
        }
        if frame.payload.len() > limit {
            out.push(Seen::Error("too large"));
            return out;
        }
        match frame.opcode {
            0x1 | 0x2 => {
                if message.is_some() {
                    out.push(Seen::Error("protocol"));
                    return out;
                }
                message = Some((frame.opcode == 0x1, Vec::new(), 1));
            }
            0x0 => match &mut message {
                None => {
                    out.push(Seen::Error("protocol"));
                    return out;
                }
                Some((_, so_far, count)) => {
                    if frame.payload.len() > limit - so_far.len() {
                        out.push(Seen::Error("too large"));
                        return out;
                    }
                    *count += 1;
                    if *count > ws_transport::MAX_MESSAGE_FRAMES {
                        out.push(Seen::Error("too fragmented"));
                        return out;
                    }
                }
            },
            _ => {}
        }
        if control {
            match frame.opcode {
                0x9 => out.push(Seen::Ping(frame.payload.clone())),
                0xA => out.push(Seen::Pong),
                _ => {
                    match frame.payload.as_slice() {
                        [] => out.push(Seen::Close(None)),
                        [_] => out.push(Seen::Error("protocol")),
                        [high, low, reason @ ..] => {
                            let code = u16::from_be_bytes([*high, *low]);
                            if !sendable_close_code(code) {
                                out.push(Seen::Error("protocol"));
                            } else if std::str::from_utf8(reason).is_err() {
                                out.push(Seen::Error("utf-8"));
                            } else {
                                out.push(Seen::Close(Some(code)));
                            }
                        }
                    }
                    return out;
                }
            }
            continue;
        }
        let (text, so_far, _) = message.as_mut().expect("a data frame has a message");
        so_far.extend_from_slice(&frame.payload);
        if *text && invalid_so_far(so_far) {
            out.push(Seen::Error("utf-8"));
            return out;
        }
        if frame.fin {
            let (text, so_far, _) = message.take().expect("checked above");
            if text {
                match String::from_utf8(so_far) {
                    Ok(text) => out.push(Seen::Text(text)),
                    Err(_) => {
                        out.push(Seen::Error("utf-8"));
                        return out;
                    }
                }
            } else {
                out.push(Seen::Binary);
            }
        }
    }
    if message.is_some() {
        out.push(Seen::Error("truncated"));
    }
    out
}

/// Read everything from `reader`, dropping the pending `next` future
/// whenever the plan says so, and return what it yielded. Panics if the
/// reader stops making progress while its stream still has bytes or has
/// not reported its end.
pub fn drain<R>(reader: &mut ws_transport::WsReader<R>, plan: &mut Plan, budget: usize) -> Vec<Seen>
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut polls = 0usize;
    'calls: loop {
        let mut call = Box::pin(reader.next());
        loop {
            polls += 1;
            assert!(polls <= budget, "the reader made no progress in {budget} polls");
            match poll_once(call.as_mut()) {
                Poll::Ready(Some(item)) => {
                    let item = seen(item);
                    let last = matches!(item, Seen::Error(_) | Seen::Close(_));
                    out.push(item);
                    drop(call);
                    if last {
                        // A finished reader stays finished.
                        let mut again = Box::pin(reader.next());
                        assert!(matches!(poll_once(again.as_mut()), Poll::Ready(None)));
                        break 'calls;
                    }
                    continue 'calls;
                }
                Poll::Ready(None) => break 'calls,
                Poll::Pending => {
                    if plan.byte() % 3 == 0 {
                        // Abandon the call; the next one must lose nothing.
                        continue 'calls;
                    }
                }
            }
        }
    }
    out
}
