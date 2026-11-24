//! Frames sent to a peer that takes them in pieces of arbitrary sizes, with
//! sends abandoned at arbitrary points, and then the closing handshake run
//! over arbitrary peer input.
//!
//! Checked: what reaches the peer is exactly the frames whose send
//! completed, each final, unmasked, without reserved bits and with its
//! length in the shortest form, followed at most by the beginning of the one
//! frame whose send was abandoned; after an abandoned send or a Close frame
//! nothing more is written; refused frames (an oversized pong, a status code
//! a Close frame cannot carry) leave no trace and do not harm the writer;
//! the closing handshake, also when the reader stopped inside a message,
//! writes one Close frame if the writer can still
//! write, nothing after it, shuts the sending side only after it, and ends.

#![no_main]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use pinchat_ws_fuzz::ws_transport::{Closing, Outgoing, WsReader, WsWriter, close};
use pinchat_ws_fuzz::{Plan, ScriptedReader, ScriptedWriter, poll_once};
use std::task::Poll;

#[derive(Arbitrary, Debug, Clone)]
enum Op {
    Text(String),
    Long(u8, u32),
    Ping,
    Pong(Vec<u8>),
    Close(Option<u16>),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum End {
    Answer(Option<u16>),
    Initiate(u16),
    Fail(u16),
    Abort,
}

#[derive(Arbitrary, Debug)]
struct Input {
    ops: Vec<(Op, u8)>,
    end: Option<End>,
    /// Polls of the reader before the handshake, which may leave it inside
    /// a message, as when the relay stops its receiving loop midway.
    pre_reads: u8,
    peer: Vec<u8>,
    plan: Vec<u8>,
}

fn sendable(code: u16) -> bool {
    (1000..=1003).contains(&code) || (1007..=1014).contains(&code) || (3000..=4999).contains(&code)
}

/// The frame a server must put on the wire for `opcode` and `payload`.
fn encoded(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    let len = payload.len();
    if len < 126 {
        out.push(len as u8);
    } else if len <= 65535 {
        out.push(126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

fn close_frame(code: Option<u16>) -> Vec<u8> {
    match code {
        Some(code) => encoded(8, &code.to_be_bytes()),
        None => encoded(8, &[]),
    }
}

fuzz_target!(|input: Input| {
    let mut plan = Plan::new(&input.plan);
    let (stream, received) = ScriptedWriter::new(Plan::new(&input.plan));
    let mut writer = WsWriter::new(stream);
    let mut expected: Vec<u8> = Vec::new();
    // The frame whose send was abandoned, if one was.
    let mut cut: Option<Vec<u8>> = None;
    let mut closed = false;
    for (op, patience) in input.ops.iter().take(64) {
        let long;
        let (frame, wire): (Outgoing<'_>, Option<Vec<u8>>) = match op {
            Op::Text(text) => (Outgoing::Text(text), Some(encoded(1, text.as_bytes()))),
            Op::Long(byte, len) => {
                long = String::from_utf8(vec![b'a' + byte % 26; *len as usize % 300_000])
                    .expect("ASCII");
                (Outgoing::Text(&long), Some(encoded(1, long.as_bytes())))
            }
            Op::Ping => (Outgoing::Ping, Some(encoded(9, &[]))),
            Op::Pong(payload) => (
                Outgoing::Pong(payload),
                (payload.len() <= 125).then(|| encoded(10, payload)),
            ),
            Op::Close(code) => (
                Outgoing::Close(*code),
                code.is_none_or(sendable).then(|| close_frame(*code)),
            ),
        };
        let usable = cut.is_none() && !closed;
        let mut send = Box::pin(writer.send(frame));
        // A patience of zero lets the send run to its end.
        let polls = if *patience == 0 { 10_000_000 } else { usize::from(*patience) };
        let mut outcome = None;
        for _ in 0..polls {
            if let Poll::Ready(result) = poll_once(send.as_mut()) {
                outcome = Some(result);
                break;
            }
            let _ = plan.byte();
        }
        drop(send);
        match (outcome, wire) {
            (Some(Err(error)), None) => {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            }
            (Some(Ok(())), Some(wire)) => {
                assert!(usable, "a frame was sent after a cut or a close");
                closed = wire[0] == 0x88;
                expected.extend(wire);
            }
            (Some(Err(error)), Some(_)) => {
                assert!(!usable, "an unexpected error: {error}");
                assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
            }
            (None, Some(wire)) => {
                assert!(*patience != 0, "a send that never ends");
                assert!(usable, "a frame was started after a cut or a close");
                cut = Some(wire);
            }
            (None, None) => panic!("a refused frame was pending"),
            (Some(Ok(())), None) => panic!("a frame that cannot be sent was sent"),
        }
    }

    if let Some(end) = input.end {
        let closing = match end {
            End::Answer(code) => Closing::Answer(code.filter(|code| sendable(*code))),
            End::Initiate(code) if sendable(code) => Closing::Initiate(code),
            End::Fail(code) if sendable(code) => Closing::Fail(code),
            _ => Closing::Abort,
        };
        let mut reader = WsReader::new(
            ScriptedReader::new(input.peer.clone(), Plan::new(&input.plan)),
            4096,
        );
        for _ in 0..input.pre_reads % 8 {
            let mut call = Box::pin(reader.next());
            for _ in 0..1 + plan.byte() % 4 {
                if poll_once(call.as_mut()).is_ready() {
                    break;
                }
            }
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        let before = received.bytes.borrow().len();
        let started = std::time::Instant::now();
        runtime.block_on(close(
            &mut writer,
            &mut reader,
            closing,
            std::time::Duration::from_secs(5),
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(4), "the handshake hung");
        let usable = cut.is_none() && !closed;
        let close_sent = received.bytes.borrow().len() > before;
        match closing {
            Closing::Abort => assert!(!close_sent),
            Closing::Answer(code) if usable => expected.extend(close_frame(code)),
            Closing::Initiate(code) | Closing::Fail(code) if usable => {
                expected.extend(close_frame(Some(code)))
            }
            _ => assert!(!close_sent, "a close frame after a cut or a close"),
        }
        if usable && closing != Closing::Abort {
            assert!(received.shut.get(), "the sending side was not shut");
        }
    }

    let written = received.bytes.borrow();
    match &cut {
        None => assert_eq!(*written, expected),
        Some(frame) => {
            assert!(written.starts_with(&expected));
            let rest = &written[expected.len()..];
            assert!(
                frame.starts_with(rest) && rest.len() <= frame.len(),
                "what follows the last whole frame is not the beginning of the cut one"
            );
        }
    }
});
