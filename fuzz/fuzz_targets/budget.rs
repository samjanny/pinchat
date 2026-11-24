//! Several connections share small tiers of the inbound budget and are read
//! in turns, each read abandoned at arbitrary points: what a relay does with
//! many peers at once.
//!
//! Checked: every connection yields what the reference model says it must,
//! whatever the others do (the budget delays, it does not change what is
//! read); no set of connections ever waits for each other for good; and
//! once they are gone the tiers are whole again.

#![no_main]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use pinchat_ws_fuzz::ws_transport::{InboundBudget, InboundTier, WsReader};
use pinchat_ws_fuzz::{FrameSpec, LengthForm, Plan, ScriptedReader, Seen, model, poll_once, seen};
use std::task::Poll;

#[derive(Arbitrary, Debug)]
struct Message {
    /// Fragments, each of this many bytes; empty means one frame.
    fragments: Vec<u16>,
    length: u32,
    ping_between: bool,
}

#[derive(Arbitrary, Debug)]
struct Connection {
    messages: Vec<Message>,
    /// The stream stops this many bytes before its end, if non-zero.
    cut: u16,
    /// Shares the address tiers of connection 0 rather than its own.
    same_address: bool,
}

#[derive(Arbitrary, Debug)]
struct Input {
    small_kib: [u8; 2],
    large_kib: [u16; 2],
    connections: Vec<Connection>,
    plan: Vec<u8>,
}

const LIMIT: usize = 150_000;

fn frames(connection: &Connection) -> Vec<FrameSpec> {
    let mut out = Vec::new();
    let frame = |fin: bool, opcode: u8, payload: Vec<u8>| FrameSpec {
        fin,
        rsv: 0,
        opcode,
        masked: true,
        mask: [0xA5, 0x5A, 0x3C, 0xC3],
        form: LengthForm::Shortest,
        payload,
    };
    for message in connection.messages.iter().take(6) {
        let total = message.length as usize % (LIMIT + 1000);
        if message.fragments.is_empty() {
            out.push(frame(true, 1, vec![b'm'; total]));
            continue;
        }
        let mut left = total;
        let mut opcode = 1;
        for (index, size) in message.fragments.iter().take(8).enumerate() {
            let last = index + 1 == message.fragments.len().min(8);
            let size = if last { left } else { left.min(usize::from(*size)) };
            left -= size;
            out.push(frame(last, opcode, vec![b'f'; size]));
            opcode = 0;
            if message.ping_between && !last {
                out.push(frame(true, 9, b"between".to_vec()));
            }
        }
    }
    out
}

fn header_len(frame: &FrameSpec) -> usize {
    match frame.payload.len() {
        0..=125 => 6,
        126..=65535 => 8,
        _ => 14,
    }
}

/// What the model says of a stream of `frames` cut after `keep` bytes.
fn expect_cut(frames: &[FrameSpec], keep: usize) -> Vec<Seen> {
    let mut whole = Vec::new();
    let mut length = 0usize;
    let mut next = None;
    for frame in frames {
        let mut encoded = Vec::new();
        frame.encode(&mut encoded);
        if length + encoded.len() <= keep {
            length += encoded.len();
            whole.push(frame.clone());
        } else {
            next = Some(frame);
            break;
        }
    }
    let prefix = model(&whole, LIMIT);
    let partial = keep - length;
    match prefix.last() {
        Some(Seen::Error(kind)) if *kind != "truncated" => return prefix,
        Some(Seen::Close(_)) => return prefix,
        _ => {}
    }
    let (Some(next), true) = (next, partial > 0) else {
        return prefix;
    };
    let mut base = prefix;
    if base.last() == Some(&Seen::Error("truncated")) {
        base.pop();
    }
    // The header of the cut frame arrived: it is checked before its body
    // is missed.
    if partial >= header_len(next) {
        let mut with_next = whole.clone();
        with_next.push(next.clone());
        let full = model(&with_next, LIMIT);
        if full.get(base.len()) == Some(&Seen::Error("too large")) {
            base.push(Seen::Error("too large"));
            return base;
        }
    }
    base.push(Seen::Error("truncated"));
    base
}

fuzz_target!(|input: Input| {
    if input.connections.is_empty() || input.connections.len() > 5 {
        return;
    }
    let small_global = InboundTier::new((usize::from(input.small_kib[0]) + 1) * 1024);
    let large_global = InboundTier::new((usize::from(input.large_kib[0]) + 1) * 1024);
    let address_tiers: Vec<(InboundTier, InboundTier)> = (0..input.connections.len())
        .map(|_| {
            (
                InboundTier::new((usize::from(input.small_kib[1]) + 1) * 1024),
                InboundTier::new((usize::from(input.large_kib[1]) + 1) * 1024),
            )
        })
        .collect();

    let mut readers = Vec::new();
    let mut counters = Vec::new();
    let mut expected = Vec::new();
    let mut total = 0usize;
    for (index, connection) in input.connections.iter().enumerate() {
        let frames = frames(connection);
        let mut wire = Vec::new();
        for frame in &frames {
            frame.encode(&mut wire);
        }
        total += wire.len();
        if total > 4 << 20 {
            return;
        }
        // A cut stream ends inside a frame, or between two.
        let keep = wire.len() - usize::from(connection.cut).min(wire.len());
        let expected_here = expect_cut(&frames, keep);
        wire.truncate(keep);
        expected.push(expected_here);
        let owner = if connection.same_address { 0 } else { index };
        let (small, large) = &address_tiers[owner];
        let budget = InboundBudget::new(
            vec![small.clone(), small_global.clone()],
            vec![large.clone(), large_global.clone()],
        );
        let stream = ScriptedReader::new(wire, Plan::new(&input.plan));
        counters.push(stream.progress());
        readers.push(WsReader::new(stream, LIMIT).with_budget(budget));
    }

    let mut plan = Plan::new(&input.plan);
    let mut got: Vec<Vec<Seen>> = vec![Vec::new(); readers.len()];
    let mut done = vec![false; readers.len()];
    let mut idle_rounds = 0usize;
    let mut rounds = 0usize;
    while done.iter().any(|done| !done) {
        rounds += 1;
        assert!(rounds < 64 * (total + 64), "no end after {rounds} rounds");
        let reads_before: usize = counters.iter().map(|counter| counter.get()).sum();
        let mut progress = false;
        for (index, reader) in readers.iter_mut().enumerate() {
            if done[index] {
                continue;
            }
            // Each turn polls a fresh call a few times and then abandons it.
            let polls = 1 + usize::from(plan.byte() % 8);
            let mut call = Box::pin(reader.next());
            for _ in 0..polls {
                match poll_once(call.as_mut()) {
                    Poll::Ready(Some(item)) => {
                        let item = seen(item);
                        if matches!(item, Seen::Error(_) | Seen::Close(_)) {
                            done[index] = true;
                        }
                        got[index].push(item);
                        progress = true;
                        break;
                    }
                    Poll::Ready(None) => {
                        done[index] = true;
                        progress = true;
                        break;
                    }
                    Poll::Pending => {}
                }
            }
        }
        let reads_after: usize = counters.iter().map(|counter| counter.get()).sum();
        if progress || reads_after > reads_before {
            idle_rounds = 0;
        } else {
            // A reader that waits for the scripted stream is ready after at
            // most a few polls; one that waits for the budget is ready once
            // another connection has asked for its next message. Many rounds
            // without any of that is a wait that never ends.
            idle_rounds += 1;
            assert!(idle_rounds < 4096, "connections wait for each other: {got:?}");
        }
    }
    for (index, (got, expected)) in got.iter().zip(&expected).enumerate() {
        assert_eq!(got, expected, "connection {index}");
    }
    drop(readers);
    assert_eq!(
        small_global.available_bytes(),
        (usize::from(input.small_kib[0]) + 1) * 1024
    );
    assert_eq!(
        large_global.available_bytes(),
        (usize::from(input.large_kib[0]) + 1) * 1024
    );
    for (small, large) in &address_tiers {
        assert_eq!(
            small.available_bytes(),
            (usize::from(input.small_kib[1]) + 1) * 1024
        );
        assert_eq!(
            large.available_bytes(),
            (usize::from(input.large_kib[1]) + 1) * 1024
        );
    }
});
