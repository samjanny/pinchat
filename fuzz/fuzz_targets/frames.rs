//! Arbitrary bytes from a peer, read in pieces of arbitrary sizes, with the
//! read abandoned at arbitrary points.
//!
//! Checked for every input: no panic and no arithmetic overflow (the build
//! has overflow checks on); the reader always finishes once the stream has
//! ended; what it allocates follows the bytes that arrived, never the
//! lengths frames announce; nothing outlives it, and every permit it took
//! from the inbound budget is back once it is dropped; a text message is
//! never above the limit; after a Close frame or an error it yields nothing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pinchat_ws_fuzz::ws_transport::{InboundBudget, InboundTier, Incoming, WsReader};
use pinchat_ws_fuzz::{Plan, ScriptedReader, live, peak, poll_once, reset_peak};
use std::task::Poll;

const LIMITS: [usize; 6] = [0, 125, 4096, 70_000, 1 << 20, 5_594_460];

fuzz_target!(|input: &[u8]| {
    if input.len() < 4 {
        return;
    }
    let (head, stream) = input.split_at(4);
    let limit = LIMITS[usize::from(head[0]) % LIMITS.len()];
    let mut plan_bytes = head[1..].to_vec();
    plan_bytes.extend(stream.iter().rev().take(64));
    let mut plan = Plan::new(&plan_bytes);

    // Tiers small enough that messages have to share them, or none.
    let tiers = match head[0] / 8 % 3 {
        0 => None,
        1 => Some((InboundTier::new(8 * 1024), InboundTier::new(100 * 1024))),
        _ => Some((InboundTier::new(16 << 20), InboundTier::new(64 << 20))),
    };
    let available = tiers
        .as_ref()
        .map(|(small, large)| (small.available_bytes(), large.available_bytes()));
    let io = ScriptedReader::new(stream.to_vec(), Plan::new(&plan_bytes));

    let base = reset_peak();
    let mut reader = WsReader::new(io, limit);
    if let Some((small, large)) = &tiers {
        reader = reader.with_budget(InboundBudget::new(vec![small.clone()], vec![large.clone()]));
    }

    let budget = 64 * (stream.len() + 16);
    let mut polls = 0usize;
    let mut finished = false;
    while !finished {
        let mut call = Box::pin(reader.next());
        loop {
            polls += 1;
            assert!(polls <= budget, "no progress after {polls} polls");
            match poll_once(call.as_mut()) {
                Poll::Ready(Some(item)) => {
                    match &item {
                        Ok(Incoming::Text(text)) => {
                            assert!(text.len() <= limit, "a text of {} bytes", text.len());
                            assert!(text.capacity() <= text.len() + 4096);
                        }
                        Ok(Incoming::Ping(payload)) => assert!(payload.len() <= 125),
                        Ok(Incoming::Close(_)) | Err(_) => finished = true,
                        Ok(_) => {}
                    }
                    break;
                }
                Poll::Ready(None) => {
                    finished = true;
                    break;
                }
                Poll::Pending => {
                    if plan.byte() % 3 == 0 {
                        break;
                    }
                }
            }
        }
    }
    let mut again = Box::pin(reader.next());
    assert!(matches!(poll_once(again.as_mut()), Poll::Ready(None)));
    drop(again);

    let (most, largest) = peak();
    let grown = most.saturating_sub(base);
    assert!(
        grown <= 2 * stream.len() + 48 * 1024,
        "{grown} bytes live for a stream of {} bytes",
        stream.len()
    );
    assert!(
        largest <= 2 * stream.len() + 8 * 1024,
        "an allocation of {largest} bytes for a stream of {} bytes",
        stream.len()
    );
    drop(reader);
    assert!(live() <= base, "the reader left memory behind");
    if let (Some((small, large)), Some(before)) = (&tiers, available) {
        assert_eq!((small.available_bytes(), large.available_bytes()), before);
    }
});
